/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#include "wanmgr_dml_dslite_apis.h"
#include "wanmgr_dslite.h"
#include "wanmgr_rdkbus_apis.h"
#include "wanmgr_data.h"

/* Get whole DSLite conf from syscfg */
ANSC_STATUS WanMgr_DSLiteInit(void)
{
    WanMgr_DSLite_Data_t *pDSLiteData;
    ANSC_STATUS ret = ANSC_STATUS_SUCCESS;

    pDSLiteData = WanMgr_GetDSLiteData_locked();
    if (!pDSLiteData)
    {
        CcspTraceError(("%s: Failed to get DSLite data lock\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    memset(pDSLiteData, 0, sizeof(*pDSLiteData));

    /* Device.DSLite.Enable */
    ret = WanMgr_SysCfgGetBool("dslite_enable", &pDSLiteData->Enable);
    if (ret != ANSC_STATUS_SUCCESS)
    {
        CcspTraceWarning(("%s: syscfg_get(dslite_enable) failed, using default 0\n", __FUNCTION__));
    }

    ret = WanMgr_SysCfgGetUint("dslite_count", &pDSLiteData->InterfaceSettingNumberOfEntries);
    if (ret != ANSC_STATUS_SUCCESS || pDSLiteData->InterfaceSettingNumberOfEntries <= 0)
    {
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(dslite_count) failed, assume 0\n", __FUNCTION__));
        }
        pDSLiteData->InterfaceSettingNumberOfEntries = 0;

        WanMgr_GetDSLiteData_release();
        return ANSC_STATUS_SUCCESS;
    }

    ret = WanMgr_SysCfgGetUint("dslite_next_insNum", &pDSLiteData->NextInstanceNumber);
    if (ret != ANSC_STATUS_SUCCESS)
    {
        CcspTraceWarning(("%s: syscfg_get(dslite_next_insNum) failed, assume InterfaceSettingNumberOfEntries + 1\n", __FUNCTION__));
        pDSLiteData->NextInstanceNumber = pDSLiteData->InterfaceSettingNumberOfEntries + 1;
    }

    for (int insNum = 1; insNum < pDSLiteData->NextInstanceNumber; insNum++)
    {
        char key[BUFLEN_64];
        ULONG tmp = 0;

        snprintf(key, sizeof(key), "dslite_InsNum_%d", insNum);
        ret = WanMgr_SysCfgGetUint(key, &tmp);
        if (ret != ANSC_STATUS_SUCCESS || tmp == 0)
        {
            /* Find existing DSLite configs by the insNum field */
            continue;
        }

        /* Sanity Check */
        if (tmp != (ULONG)insNum)
        {
            CcspTraceError(("%s: syscfg_get(%s) returned mismatched insNum %lu (expected %d), skipping\n",
                              __FUNCTION__, key, tmp, insNum));
            continue;
        }

        DML_DSLITE_LIST *entry = (DML_DSLITE_LIST *)AnscAllocateMemory(sizeof(DML_DSLITE_LIST));
        if (!entry)
        {
            CcspTraceError(("%s: Allocation failed for DML_DSLITE_LIST (insNum=%d)\n", __FUNCTION__, insNum));
            ret = ANSC_STATUS_RESOURCES;
            break;
        }
        entry->InstanceNumber = insNum;

        DML_DSLITE_CONFIG cfg;
        DSLITE_SET_DEFAULTVALUE(&cfg);  /* start from known defaults */

        snprintf(key, sizeof(key), "dslite_active_%d", insNum);
        ret = WanMgr_SysCfgGetBool(key, &cfg.Enable);
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, using default Enable=%d\n", __FUNCTION__, key, cfg.Enable));
        }

        snprintf(key, sizeof(key), "dslite_alias_%d", insNum);
        ret = WanMgr_SysCfgGetStr(key, cfg.Alias, sizeof(cfg.Alias));
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, Alias empty\n", __FUNCTION__, key));
            cfg.Alias[0] = '\0';
        }

        snprintf(key, sizeof(key), "dslite_mode_%d", insNum);
        int mode = cfg.Mode;
        ret = WanMgr_SysCfgGetUint(key, &mode);
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, using default mode=%d\n", __FUNCTION__, key, mode));
        }
        cfg.Mode = (DML_WAN_DSLITE_ADDR_METHOD)mode;

        snprintf(key, sizeof(key), "dslite_addr_type_%d", insNum);
        int atype = cfg.Type;
        ret = WanMgr_SysCfgGetUint(key, &atype);
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, using default addr_type=%d\n", __FUNCTION__, key, atype));
        }
        cfg.Type = (DML_WAN_DSLITE_ADDR_PRECEDENCE)atype;

        snprintf(key, sizeof(key), "dslite_addr_fqdn_%d", insNum);
        ret = WanMgr_SysCfgGetStr(key, cfg.AddrFqdn, sizeof(cfg.AddrFqdn));
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, EndpointName empty\n", __FUNCTION__, key));
        }

        snprintf(key, sizeof(key), "dslite_addr_ipv6_%d", insNum);
        ret = WanMgr_SysCfgGetStr(key, cfg.AddrIPv6, sizeof(cfg.AddrIPv6));
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, EndpointAddress empty\n", __FUNCTION__, key));
        }

        snprintf(key, sizeof(key), "dslite_mss_clamping_enable_%d", insNum);
        ret = WanMgr_SysCfgGetUint(key, &cfg.MssClampingEnable);
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, using default MssClampingEnable=%d\n", __FUNCTION__, key, cfg.MssClampingEnable));
        }

        snprintf(key, sizeof(key), "dslite_tcpmss_%d", insNum);
        int tcpMssTmp = (int)cfg.TcpMss;
        ret = WanMgr_SysCfgGetUint(key, &tcpMssTmp);
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, using default TcpMss=%lu\n", __FUNCTION__, key, cfg.TcpMss));
        }
        else
        {
            cfg.TcpMss = (ULONG)tcpMssTmp;
        }

        snprintf(key, sizeof(key), "dslite_ipv6_frag_enable_%d", insNum);
        ret = WanMgr_SysCfgGetBool(key, &cfg.Ipv6FragEnable);
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, using default Ipv6FragEnable=%d\n", __FUNCTION__, key, cfg.Ipv6FragEnable));
        }

        snprintf(key, sizeof(key), "dslite_status_%d", insNum);
        int statusVal = cfg.Status;
        ret = WanMgr_SysCfgGetUint(key, &statusVal);
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, using default Status=%d\n", __FUNCTION__, key, statusVal));
        }
        cfg.Status = (DML_WAN_IFACE_DSLITE_STATUS)statusVal;

        snprintf(key, sizeof(key), "dslite_addr_inuse_%d", insNum);
        ret = WanMgr_SysCfgGetStr(key, cfg.AddrInUse, sizeof(cfg.AddrInUse));
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, EndpointAddressInUse empty\n", __FUNCTION__, key));
        }

        snprintf(key, sizeof(key), "dslite_origin_%d", insNum);
        int origin = cfg.Origin;
        ret = WanMgr_SysCfgGetUint(key, &origin);
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, using default Origin=%d\n", __FUNCTION__, key, origin));
        }
        cfg.Origin = (DML_WAN_DSLITE_ADDR_METHOD)origin;

        snprintf(key, sizeof(key), "dslite_tunnel_interface_%d", insNum);
        ret = WanMgr_SysCfgGetStr(key, cfg.TunnelIface, sizeof(cfg.TunnelIface));
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, TunnelInterface empty\n", __FUNCTION__, key));
        }

        snprintf(key, sizeof(key), "dslite_tunneled_interface_%d", insNum);
        ret = WanMgr_SysCfgGetStr(key, cfg.TunneledIface, sizeof(cfg.TunneledIface));
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, TunneledInterface empty\n", __FUNCTION__, key));
        }

        snprintf(key, sizeof(key), "dslite_tunnel_v4addr_%d", insNum);
        ret = WanMgr_SysCfgGetStr(key, cfg.TunnelV4Addr, sizeof(cfg.TunnelV4Addr));
        if (ret != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: syscfg_get(%s) failed, TunnelV4Addr empty\n", __FUNCTION__, key));
        }

        entry->PrevCfg          = cfg;
        entry->CurrCfg          = cfg;
        entry->next             = pDSLiteData->DSLiteList;
        pDSLiteData->DSLiteList = entry;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

