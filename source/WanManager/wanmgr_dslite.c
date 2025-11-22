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

#include <event2/event.h>
#include <event2/dns.h>

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
        return ANSC_STATUS_FAILURE;

    memset(pDSLiteData, 0, sizeof(*pDSLiteData));

    /* Device.DSLite.Enable */
    WanMgr_SysCfgGetBool("dslite_enable", &pDSLiteData->Enable);
    WanMgr_SysCfgGetUint("dslite_count", &pDSLiteData->InterfaceSettingNumberOfEntries);
    if (WanMgr_SysCfgGetUint("dslite_next_insNum", &pDSLiteData->NextInstanceNumber) != ANSC_STATUS_SUCCESS)
    {
        /* assume InterfaceSettingNumberOfEntries + 1 */
        pDSLiteData->NextInstanceNumber = pDSLiteData->InterfaceSettingNumberOfEntries + 1;
    }

    for (UINT insNum = 1; insNum < pDSLiteData->NextInstanceNumber; insNum++)
    {
        DML_DSLITE_LIST *entry;
        char key[BUFLEN_64];
        UINT tmp = 0;

        snprintf(key, sizeof(key), "dslite_InsNum_%d", insNum);
        ret = WanMgr_SysCfgGetUint(key, &tmp);
        if (ret != ANSC_STATUS_SUCCESS || tmp == 0)
        {
            /* Find existing DSLite configs by the insNum field */
            continue;
        }

        /* Sanity Check */
        if (tmp != insNum)
        {
            CcspTraceError(("%s: syscfg_get(%s) returned mismatched insNum %lu (expected %d), skipping\n",
                              __FUNCTION__, key, tmp, insNum));
            continue;
        }

        entry = (DML_DSLITE_LIST *)AnscAllocateMemory(sizeof(DML_DSLITE_LIST));
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
        WanMgr_SysCfgGetBool(key, &cfg.Enable);

        snprintf(key, sizeof(key), "dslite_alias_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.Alias, sizeof(cfg.Alias));

        snprintf(key, sizeof(key), "dslite_mode_%d", insNum);
        WanMgr_SysCfgGetUint(key, &cfg.Mode);

        snprintf(key, sizeof(key), "dslite_addr_type_%d", insNum);
        WanMgr_SysCfgGetUint(key, &cfg.Type);

        snprintf(key, sizeof(key), "dslite_addr_fqdn_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.AddrFqdn, sizeof(cfg.AddrFqdn));

        snprintf(key, sizeof(key), "dslite_addr_ipv6_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.AddrIPv6, sizeof(cfg.AddrIPv6));

        snprintf(key, sizeof(key), "dslite_mss_clamping_enable_%d", insNum);
        WanMgr_SysCfgGetBool(key, &cfg.MssClampingEnable);

        snprintf(key, sizeof(key), "dslite_tcpmss_%d", insNum);
        WanMgr_SysCfgGetUint(key, &cfg.TcpMss);

        snprintf(key, sizeof(key), "dslite_ipv6_frag_enable_%d", insNum);
        WanMgr_SysCfgGetBool(key, &cfg.Ipv6FragEnable);

        snprintf(key, sizeof(key), "dslite_status_%d", insNum);
        WanMgr_SysCfgGetUint(key, &cfg.Status);

        snprintf(key, sizeof(key), "dslite_addr_inuse_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.AddrInUse, sizeof(cfg.AddrInUse));

        snprintf(key, sizeof(key), "dslite_origin_%d", insNum);
        WanMgr_SysCfgGetUint(key, &cfg.Origin);

        snprintf(key, sizeof(key), "dslite_tunnel_interface_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.TunnelIface, sizeof(cfg.TunnelIface));

        snprintf(key, sizeof(key), "dslite_tunneled_interface_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.TunneledIface, sizeof(cfg.TunneledIface));

        snprintf(key, sizeof(key), "dslite_tunnel_v4addr_%d", insNum);
        WanMgr_SysCfgGetStr(key, cfg.TunnelV4Addr, sizeof(cfg.TunnelV4Addr));

        entry->PrevCfg          = cfg;
        entry->CurrCfg          = cfg;
        entry->next             = pDSLiteData->DSLiteList;
        pDSLiteData->DSLiteList = entry;
    }

    WanMgr_GetDSLiteData_release();
    return ret;
}

static void _get_shell_output(FILE *fp, char *buf, size_t len)
{
    if (len > 0)
        buf[0] = 0;

    buf = fgets(buf, len, fp);

    if ((len > 0) && (buf != NULL))
    {
        len = strlen(buf);
        if ((len > 0) && (buf[len - 1] == '\n'))
            buf[len - 1] = 0;
    }
}

static void restart_zebra (void)
{
    FILE *zebra_pid_fd;
    FILE *zebra_cmdline_fd;
    char pid_str[10];
    char cmdline_buf[255];
    int pid = -1;
    int restart_needed = 1;

    if ((zebra_pid_fd = fopen("/var/zebra.pid", "rb")) != NULL)
    {
        if (fgets(pid_str, sizeof(pid_str), zebra_pid_fd) != NULL && atoi(pid_str) > 0)
        {
            pid = atoi(pid_str);
        }
        fclose(zebra_pid_fd);
    }

    if (pid > 0)
    {
        sprintf(cmdline_buf, "/proc/%d/cmdline", pid);
        if ((zebra_cmdline_fd = fopen(cmdline_buf, "rb")) != NULL)
        {
            if (fgets(cmdline_buf, sizeof(cmdline_buf), zebra_cmdline_fd) != NULL)
            {
                if (strstr(cmdline_buf, "zebra"))
                {
                    restart_needed = 0;
                }
            }
            fclose(zebra_cmdline_fd);
        }
    }

    if (restart_needed)
    {
        sysevent_set(sysevent_fd, sysevent_token, "zebra-restart", "", 0);
    }
}
static void WanMgr_RouteConfig(const char *if_name)
{
    char cmd[256];

    if (!if_name || if_name[0] == '\0')
        return;

    snprintf(cmd, sizeof(cmd),
             "ip rule add iif %s lookup all_lans; "
             "ip rule add oif %s lookup erouter",
             if_name,
             if_name);

    WanManager_DoSystemAction("WanMgr_RouteConfig:", cmd);
}


static void WanMgr_RouteDeconfig(const char *if_name)
{
    char wan_ip[64] = {0};
    char cmd[512];

    if (!if_name || if_name[0] == '\0')
    {
        return;
    }

    /* Fetch current WAN IPv4 address from sysevent */
    sysevent_get(sysevent_fd, sysevent_token, "current_wan_ipaddr", wan_ip, sizeof(wan_ip));

    if (wan_ip[0] != '\0')
    {
        snprintf(cmd, sizeof(cmd),
                 "ip rule del from %s lookup all_lans; "
                 "ip rule del from %s lookup erouter; "
                 "ip rule del iif %s lookup all_lans; "
                 "ip rule del oif %s lookup erouter",
                 wan_ip,
                 wan_ip,
                 if_name,
                 if_name);
    }
    else
    {
        /* Only delete interface-based rules if IP is missing */
        snprintf(cmd, sizeof(cmd),
                 "ip rule del iif %s lookup all_lans; "
                 "ip rule del oif %s lookup erouter",
                 if_name,
                 if_name);
    }

    WanManager_DoSystemAction("WanMgr_RouteDeconfig:", cmd);
}

static int dslite_get_instance_from_path(const char *path, UINT *inst_out)
{
    char         tmp[256];
    size_t       len;
    char        *last;
    const char  *numstr;
    char        *endptr;
    long         idx;

    if (!path || !inst_out)
        return -1;

    memset(tmp, 0, sizeof(tmp));
    strncpy(tmp, path, sizeof(tmp) - 1);

    len = strlen(tmp);
    while (len > 0 && tmp[len - 1] == '.')
    {
        tmp[len - 1] = '\0';
        --len;
    }

    if (len == 0)
        return -1;

    last   = strrchr(tmp, '.');
    numstr = last ? last + 1 : tmp;
    if (!numstr || *numstr == '\0')
        return -1;

    idx = strtol(numstr, &endptr, 10);
    if (endptr == numstr || idx <= 0)
        return -1;

    *inst_out = (UINT)idx;
    return 0;
}

/* AFTR selection based on DML config (Mode/Type) */
static int WanMgr_DSLite_GetAFTR(const DML_DSLITE_CONFIG *cfg, UINT inst, char *aftrBuf, size_t aftrBufLen)
{
    char tmp[256] = {0};
    char key[128] = {0};
    const char *src = NULL;

    if (!cfg || !aftrBuf || aftrBufLen == 0)
    {
        return -1;
    }

    aftrBuf[0] = '\0';

    /* DHCPv6 mode: AFTR comes from sysevent */
    if (cfg->Mode == DSLITE_ENDPOINT_DHCPV6)
    {

        // TBD: Currently, we are getting AFTR from sysevent. Do we need to continue doing it this way? If yes, what should the sysevent name be?
        sysevent_get(sysevent_fd, sysevent_token, "dslite_dhcpv6_endpointname", tmp, sizeof(tmp));

        if (tmp[0] == '\0')
        {
            return -1;
        }

        src = tmp;
    }
    else if (cfg->Mode == DSLITE_ENDPOINT_STATIC)
    {

        if (cfg->Type == DSLITE_ENDPOINT_FQDN)
        {
            src = cfg->AddrFqdn;
        }
        else if (cfg->Type == DSLITE_ENDPOINT_IPV6ADDRESS)
        {
            src = cfg->AddrIPv6;
        }

        if (!src || src[0] == '\0')
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    strncpy(aftrBuf, src, aftrBufLen - 1);
    return (int)cfg->Mode;
}

/* DNS resolver (libevent/evdns) – IPv6 AAAA for AFTR FQDN */
typedef struct
{
    struct event_base *base;
    struct in6_addr *result;
    int ttl;
} DSLITE_DNS_CTX;

static void dslite_dns_cb(int result, char type, int count, int ttl, void *addresses, void *arg)
{
    DSLITE_DNS_CTX *ctx = (DSLITE_DNS_CTX *)arg;

    if (!ctx)
    {
        return;
    }

    ctx->result = NULL;
    ctx->ttl = 0;

    if (result == DNS_ERR_NONE &&
        type == DNS_IPv6_AAAA &&
        count > 0 &&
        addresses != NULL)
    {
        ctx->result = (struct in6_addr *)malloc(sizeof(struct in6_addr));
        if (ctx->result)
        {
            memcpy(ctx->result, addresses, sizeof(struct in6_addr));
            ctx->ttl = ttl;
        }
    }

    if (ctx->base)
    {
        event_base_loopexit(ctx->base, NULL);
    }
}

static struct in6_addr *dslite_resolve_fqdn_to_ipv6addr(const char *fqdn, unsigned int *dnsttl, const char *nameserver)
{
    struct event_base *evbase = NULL;
    struct evdns_base *dns_base = NULL;
    struct evdns_request *req = NULL;
    DSLITE_DNS_CTX ctx;
    struct in6_addr *ret = NULL;

    if (!fqdn || !nameserver)
    {
        return NULL;
    }

    memset(&ctx, 0, sizeof(ctx));

    evbase = event_base_new();
    if (!evbase)
    {
        return NULL;
    }
    ctx.base = evbase;

    dns_base = evdns_base_new(evbase, 0);
    if (!dns_base)
    {
        event_base_free(evbase);
        return NULL;
    }

    evdns_base_nameserver_ip_add(dns_base, nameserver);

    req = evdns_base_resolve_ipv6(dns_base, fqdn, DNS_QUERY_NO_SEARCH, dslite_dns_cb, &ctx);
    if (!req)
    {
        evdns_base_free(dns_base, 0);
        event_base_free(evbase);
        return NULL;
    }

    event_base_dispatch(evbase);

    if (ctx.result)
    {
        ret = ctx.result;
    }

    if (dnsttl)
    {
        *dnsttl = (ret ? (unsigned int)ctx.ttl : 0);
    }

    evdns_base_free(dns_base, 0);
    event_base_free(evbase);

    return ret;
}


ANSC_STATUS WanMgr_DSLite_SetupTunnel(DML_VIRTUAL_IFACE *pVirtIf)
{
    UINT                inst = 0;
    char                status_key[64];
    char                tunnelIf[64];
    char                wan6_addr[128];
    char                dns_list[2][128];
    int                 dns_count = 0;

    DML_DSLITE_LIST    *entry = NULL;
    DML_DSLITE_CONFIG  *cfg   = NULL;

    char                aftr_buf[256]       = {0};
    char                tnl_v4_addr[64]     = {0};
    char                resolved_aftr[256]  = {0};
    struct in6_addr     tmpv6;
    struct in6_addr    *addrp   = NULL;
    unsigned int        dns_ttl = 0;

    char                tnl_ipv6[64]        = {0};
    int                 rc = 0;
    int                 mode = 0;

    if (!pVirtIf || !pVirtIf->DSLite.Path || !pVirtIf->Name)
    {
        CcspTraceError(("%s: Invalid input parameters\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if (pVirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_UP)
    {
        CcspTraceInfo(("%s: Already UP, skipping setup\n", __FUNCTION__));
        return ANSC_STATUS_SUCCESS;
    }

    //TBD: Is this the right way to get the instance number?
    if (dslite_get_instance_from_path(pVirtIf->DSLite.Path, &inst) != 0)
    {
        CcspTraceError(("%s: Failed to get DSLite instance for path %s\n", __FUNCTION__, pVirtIf->DSLite.Path));
        return ANSC_STATUS_FAILURE;
    }

    snprintf(status_key, sizeof(status_key), "dslite_service-status_%u", inst);
    sysevent_set(sysevent_fd, sysevent_token, status_key, "starting", 0);

    snprintf(tunnelIf, sizeof(tunnelIf), "ipip6tun%u", inst ? inst - 1 : 0);
    CcspTraceInfo(("%s: Starting DSLite setup for instance %u using tunnel interface %s\n", __FUNCTION__, inst, tunnelIf));

    memset(wan6_addr, 0, sizeof(wan6_addr));
    memset(dns_list, 0, sizeof(dns_list));

    strncpy(wan6_addr, pVirtIf->IP.Ipv6Data.address, sizeof(wan6_addr) - 1);

    if (pVirtIf->IP.Ipv6Data.nameserver[0] != '\0')
        strncpy(dns_list[dns_count++], pVirtIf->IP.Ipv6Data.nameserver, sizeof(dns_list[0]) - 1);

    if (pVirtIf->IP.Ipv6Data.nameserver1[0] != '\0')
        strncpy(dns_list[dns_count++], pVirtIf->IP.Ipv6Data.nameserver1, sizeof(dns_list[1]) - 1);

    if (strlen(wan6_addr) < 2 || dns_count == 0)
    {
        CcspTraceError(("%s: Invalid WAN IPv6 (%s) or no DNS servers (count=%d)\n", __FUNCTION__, wan6_addr, dns_count));
        sysevent_set(sysevent_fd, sysevent_token, status_key, "error", 0);
        return ANSC_STATUS_FAILURE;
    }

    entry = WanMgr_getDSLiteCfgByInstance_locked(inst);
    if (!entry)
    {
        sysevent_set(sysevent_fd, sysevent_token, status_key, "error", 0);
        return ANSC_STATUS_FAILURE;
    }

    cfg = &entry->CurrCfg;

    /* Get AFTR Mode & Address */
    mode = WanMgr_DSLite_GetAFTR(cfg, inst, aftr_buf, sizeof(aftr_buf));
    CcspTraceInfo(("%s: AFTR mode=%d, AFTR buffer=%s\n", __FUNCTION__, mode, aftr_buf));

    /* Copy TunnelV4Addr to local variable */
    if (cfg->TunnelV4Addr[0] != '\0')
    {
        strncpy(tnl_v4_addr, cfg->TunnelV4Addr, sizeof(tnl_v4_addr) - 1);
    }

    WanMgr_GetDSLiteData_release();

    if (mode < 0)
    {
        sysevent_set(sysevent_fd, sysevent_token, status_key, "error", 0);
        return ANSC_STATUS_FAILURE;
    }

    /* Construct Tunnel IPv6 ("40"+suffix) */
    if (strlen(wan6_addr) >= 2)
    {
        tnl_ipv6[0] = '4';
        tnl_ipv6[1] = '0';
        strncpy(&tnl_ipv6[2], &wan6_addr[2], sizeof(tnl_ipv6) - 3);
        tnl_ipv6[sizeof(tnl_ipv6) - 1] = '\0';
    }

    /* Resolve AFTR FQDN to IP */
    if (inet_pton(AF_INET6, aftr_buf, &tmpv6) == 1)
    {
        CcspTraceInfo(("%s: AFTR address is already IPv6 literal: %s\n", __FUNCTION__, resolved_aftr));
        strncpy(resolved_aftr, aftr_buf, sizeof(resolved_aftr) - 1);
    }
    else
    {
        CcspTraceInfo(("%s: Resolving AFTR FQDN %s\n", __FUNCTION__, aftr_buf));

        for (int i = 0; i < dns_count && resolved_aftr[0] == '\0'; i++)
        {
            CcspTraceInfo(("%s: Trying DNS %s\n", __FUNCTION__, dns_list[i]));
            addrp = dslite_resolve_fqdn_to_ipv6addr(aftr_buf, &dns_ttl, dns_list[i]);
            if (addrp)
            {
                inet_ntop(AF_INET6, addrp, resolved_aftr, sizeof(resolved_aftr));
                free(addrp);
            }
        }

        if (resolved_aftr[0] == '\0' || strcmp(resolved_aftr, "::") == 0)
        {
            CcspTraceError(("%s: Unable to resolve AFTR FQDN\n", __FUNCTION__));
            sysevent_set(sysevent_fd, sysevent_token, status_key, "dns_error", 0);
            return ANSC_STATUS_FAILURE;
        }
    }

    CcspTraceInfo(("%s: AFTR resolved to %s\n", __FUNCTION__, resolved_aftr));
    WanMgr_RouteDeconfig(pVirtIf->Name);
    //TO DO: Do we really need to stop the V4 client?
    WanManager_StopDhcpv4Client(pVirtIf, STOP_DHCP_WITH_RELEASE);

    sysevent_set(sysevent_fd, sysevent_token, "current_wan_ipaddr", "0.0.0.0", 0);

    /* Create tunnel interface */
    rc = v_secure_system(
        "ip -6 tunnel add %s mode ip4ip6 remote %s local %s dev %s encaplimit none tos inherit",
        tunnelIf, resolved_aftr, wan6_addr, pVirtIf->Name
    );

    if (rc != 0)
    {
        CcspTraceError(("%s: Failed to create tunnel interface %s\n", __FUNCTION__, tunnelIf));
        sysevent_set(sysevent_fd, sysevent_token, status_key, "error", 0);
        return ANSC_STATUS_FAILURE;
    }

    /* Enable IPv6 Autoconf */
    sysctl_iface_set("/proc/sys/net/ipv6/conf/%s/autoconf", tunnelIf, "1");

    /* Configure Addresses (Using tnl_v4_addr) */
    if (tnl_v4_addr[0] != '\0')
    {
        v_secure_system("ip link set dev %s txqueuelen 1000 up; "
                        "ip -6 addr add %s dev %s; "
                        "ip addr add %s dev %s; "
                        "ip -4 addr flush %s",
                        tunnelIf,
                        tnl_ipv6, tunnelIf,
                        tnl_v4_addr, tunnelIf, /* Safe: using local stack copy */
                        pVirtIf->Name);
    }
    else
    {
        v_secure_system("ip link set dev %s txqueuelen 1000 up; "
                        "ip -6 addr add %s dev %s; "
                        "ip -4 addr flush %s",
                        tunnelIf,
                        tnl_ipv6, tunnelIf,
                        pVirtIf->Name);
    }

    /* Configure Routes */
    v_secure_system("ip route add default dev %s table erouter", tunnelIf);
    v_secure_system("ip route add default dev %s table 14", tunnelIf);

    // IPv6 only mode, we need to start the LAN to WAN IPv4 function
    if (pVirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY)
    {
        sysctl_iface_set ("/proc/sys/net/ipv4/ip_forward", NULL, "1");
    }
    else
    {
        /* Restart the LAN side DHCPv4 server, DNS proxy and IGMP proxy if in dual stack mode */
#if defined(_LG_OFW_)
        v_secure_system ("/etc/utopia/service.d/service_dhcp_server.sh dhcp_server-stop" "; "
                "/etc/utopia/service.d/service_dhcp_server.sh dhcp_server-start" "; "
                "/etc/utopia/service.d/service_mcastproxy.sh mcastproxy-restart");
#else
        v_secure_system ("systemctl stop dnsmasq.service" "; "
                "systemctl start dnsmasq.service" "; "
                "/etc/utopia/service.d/service_mcastproxy.sh mcastproxy-restart");
#endif
    }

    entry = WanMgr_getDSLiteCfgByInstance_locked(inst);
    if (!entry)
    {
        sysevent_set(sysevent_fd, sysevent_token, status_key, "error", 0);
        return ANSC_STATUS_FAILURE;
    }

    cfg = &entry->CurrCfg;

    /* Firewall rules for DSLite tunnel interface */
    {
        CcspTraceInfo(("%s: Adding firewall rules for tunnel %s\n", __FUNCTION__, tunnelIf));
        char fw_rule[256];
        char fw_retbuf[256];
        char fw_id_key[64];
        char rule_mss[256] = {0};
        char rule_mss2[256] = {0};
        char return_buffer[256] = {0};
        memset(fw_retbuf, 0, sizeof(fw_retbuf));
        snprintf(fw_rule, sizeof(fw_rule), "-I FORWARD -o %s -j ACCEPT\n", tunnelIf);
        sysevent_set_unique(sysevent_fd, sysevent_token, "GeneralPurposeFirewallRule", fw_rule, fw_retbuf, sizeof(fw_retbuf));

        snprintf(fw_id_key, sizeof(fw_id_key), "dslite_rule_sysevent_id_%u_1", inst);
        sysevent_set(sysevent_fd, sysevent_token, fw_id_key, fw_retbuf, 0);

        memset(fw_retbuf, 0, sizeof(fw_retbuf));
        snprintf(fw_rule, sizeof(fw_rule), "-I FORWARD -i %s -j ACCEPT\n", tunnelIf);
        sysevent_set_unique(sysevent_fd, sysevent_token, "GeneralPurposeFirewallRule", fw_rule, fw_retbuf, sizeof(fw_retbuf));

        snprintf(fw_id_key, sizeof(fw_id_key), "dslite_rule_sysevent_id_%u_2", inst);
        sysevent_set(sysevent_fd, sysevent_token, fw_id_key, fw_retbuf, 0);
        if (cfg->MssClampingEnable)
        {
            if (cfg->TcpMss <= 1460 && cfg->TcpMss > 0)
            {
                snprintf(rule_mss, sizeof(rule_mss), "-I FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %lu\n", tunnelIf, cfg->TcpMss);
                snprintf(rule_mss2, sizeof(rule_mss2), "-I FORWARD -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %lu\n", tunnelIf, cfg->TcpMss);
            }
            else
            {
                snprintf(rule_mss, sizeof(rule_mss), "-I FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n", tunnelIf);
                snprintf(rule_mss2, sizeof(rule_mss2), "-I FORWARD -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n", tunnelIf);
            }

            memset(return_buffer, 0, sizeof(return_buffer));
            sysevent_set_unique(sysevent_fd, sysevent_token, "GeneralPurposeMangleRule", rule_mss, return_buffer, sizeof(return_buffer));

            snprintf(fw_id_key, sizeof(fw_id_key), "dslite_rule_sysevent_id_%u_3", inst);
            sysevent_set(sysevent_fd, sysevent_token, fw_id_key, return_buffer, 0);

            memset(return_buffer, 0, sizeof(return_buffer));
            sysevent_set_unique(sysevent_fd, sysevent_token, "GeneralPurposeMangleRule", rule_mss2, return_buffer, sizeof(return_buffer));

            snprintf(fw_id_key, sizeof(fw_id_key), "dslite_rule_sysevent_id_%u_4", inst);
            sysevent_set(sysevent_fd, sysevent_token, fw_id_key, return_buffer, 0);
        }
    }

    strncpy(cfg->AddrInUse, resolved_aftr, sizeof(cfg->AddrInUse) - 1);
    strncpy(cfg->TunnelIface, tunnelIf, sizeof(cfg->TunnelIface) - 1);
    strncpy(cfg->TunneledIface, pVirtIf->Name, sizeof(cfg->TunneledIface) - 1);

    cfg->Origin = (mode == DSLITE_ENDPOINT_DHCPV6) ? DSLITE_ENDPOINT_DHCPV6 : DSLITE_ENDPOINT_STATIC;
    cfg->Status = WAN_IFACE_DSLITE_STATE_UP;

    WanMgr_GetDSLiteData_release();
    WanMgr_DSLite_WriteEntryCfgToSyscfg(inst);

    v_secure_system("sysevent set firewall-restart; conntrack_flush");
    sysevent_set(sysevent_fd, sysevent_token, status_key, "started", 0);
    CcspTraceInfo(("%s: DSLITE setup complete for instance %u (tunnel=%s)\n", __FUNCTION__, inst, tunnelIf));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_DSLite_TeardownTunnel(DML_VIRTUAL_IFACE *pVirtIf)
{
    UINT                inst = 0;
    char                tunnelIf[64];
    char                status_key[64];
    char                cmd[512];
    char                remote_addr[64] = {0};
    char                local_addr[64]  = {0};
    FILE               *fp = NULL;

    DML_DSLITE_LIST    *entry = NULL;
    DML_DSLITE_CONFIG  *cfg   = NULL;

    if (!pVirtIf || !pVirtIf->DSLite.Path || !pVirtIf->Name)
    {
        CcspTraceError(("%s: Invalid input parameters\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    if (pVirtIf->DSLite.Status == WAN_IFACE_DSLITE_STATE_DOWN)
    {
         CcspTraceInfo(("%s: Already DOWN, nothing to tear down\n", __FUNCTION__));
        return ANSC_STATUS_SUCCESS;
    }

    //TBD: Is this the right way to get the instance number?
    if (dslite_get_instance_from_path(pVirtIf->DSLite.Path, &inst) != 0)
    {
        CcspTraceError(("%s: Failed to get instance from path %s\n", __FUNCTION__, pVirtIf->DSLite.Path));
        return ANSC_STATUS_FAILURE;
    }

    snprintf(tunnelIf, sizeof(tunnelIf), "ipip6tun%u", (unsigned int)(inst ? inst - 1 : 0));
    snprintf(status_key, sizeof(status_key), "dslite_service-status_%u", inst);
    CcspTraceInfo(("%s: Tearing down DSLITE inst=%u tunnel=%s\n", __FUNCTION__, inst, tunnelIf));

    sysevent_set(sysevent_fd, sysevent_token, status_key, "stopping", 0);

    /* Get Remote Address */
    snprintf(cmd, sizeof(cmd), "ip -6 tunnel show | grep %s | awk '/remote/{print $4}'", tunnelIf);
    fp = v_secure_popen("r", "%s", cmd);
    if (fp)
    {
        _get_shell_output(fp, remote_addr, sizeof(remote_addr));
        v_secure_pclose(fp);
        CcspTraceInfo(("%s: Remote addr=%s\n", __FUNCTION__, remote_addr));
    }

    /* Get Local Address */
    snprintf(cmd, sizeof(cmd), "ip -6 tunnel show | grep %s | awk '/remote/{print $6}'", tunnelIf);
    fp = v_secure_popen("r", "%s", cmd);
    if (fp)
    {
        _get_shell_output(fp, local_addr, sizeof(local_addr));
        v_secure_pclose(fp);
        CcspTraceInfo(("%s: Local addr=%s\n", __FUNCTION__, local_addr));
    }

    if ((strlen(remote_addr) != 0) && (strlen(local_addr) != 0))
    {
        CcspTraceInfo(("%s: Removing tunnel \n", __FUNCTION__));
        v_secure_system("ip -6 tunnel del %s mode ip4ip6 remote %s local %s dev %s encaplimit none", tunnelIf, remote_addr, local_addr, pVirtIf->Name);

        /*restart the zebra process if it's exited*/
        restart_zebra();
    }
    else
    {
        v_secure_system("ip -6 tunnel del %s", tunnelIf);
    }

    entry = WanMgr_getDSLiteCfgByInstance_locked(inst);
    if (entry)
    {
        cfg = &entry->CurrCfg;
        cfg->AddrInUse[0] = '\0';
        cfg->TunnelIface[0]      = '\0';
        cfg->TunneledIface[0]    = '\0';
        cfg->Status                  = WAN_IFACE_DSLITE_STATE_DOWN;

        WanMgr_GetDSLiteData_release();
        WanMgr_DSLite_WriteEntryCfgToSyscfg(inst);
    }


    if (pVirtIf->IP.Mode != DML_WAN_IP_MODE_IPV6_ONLY)
    {
        //Start WAN IPv4 service
        WanMgr_RouteConfig(pVirtIf->Name);
        //TO DO: Do we really need to start the client?
        // WanManager_StartDhcpv4Client(pVirtIf, pVirtIf->Name, 1);
    }

    // Restore default gateway route rule
    v_secure_system("ip route del default dev %s table erouter", tunnelIf);
    v_secure_system("ip route del default dev %s table 14", tunnelIf);

    // if VIF is the IPv6 only mode, we need to shutdown the LAN to WAN IPv4 function
    if (pVirtIf->IP.Mode == DML_WAN_IP_MODE_IPV6_ONLY)
    {
        sysctl_iface_set("/proc/sys/net/ipv4/ip_forward", NULL, "0");
    }
    else
    {
        /* Restart the LAN side DHCPv4 server, DNS proxy and IGMP proxy if in dual stack mode */
#if defined(_LG_OFW_)
        v_secure_system ("/etc/utopia/service.d/service_dhcp_server.sh dhcp_server-stop" "; "
                "/etc/utopia/service.d/service_dhcp_server.sh dhcp_server-start" "; "
                "/etc/utopia/service.d/service_mcastproxy.sh mcastproxy-restart");
#else
        v_secure_system ("systemctl stop dnsmasq.service" "; "
                "systemctl start dnsmasq.service" "; "
                "/etc/utopia/service.d/service_mcastproxy.sh mcastproxy-restart");
#endif
    }

    /* Firewall rules for DSLite tunnel interface */
    {
        char fw_id_key[64];
        char fw_rule_id[64];

        snprintf(fw_id_key, sizeof(fw_id_key), "dslite_rule_sysevent_id_%u_1", inst);
        memset(fw_rule_id, 0, sizeof(fw_rule_id));
        sysevent_get(sysevent_fd, sysevent_token, fw_id_key, fw_rule_id, sizeof(fw_rule_id));

        if (fw_rule_id[0] != '\0')
        {
            sysevent_set(sysevent_fd, sysevent_token, fw_rule_id, "", 0);
            sysevent_set(sysevent_fd, sysevent_token, fw_id_key, "", 0);
        }

        snprintf(fw_id_key, sizeof(fw_id_key), "dslite_rule_sysevent_id_%u_2", inst);
        memset(fw_rule_id, 0, sizeof(fw_rule_id));
        sysevent_get(sysevent_fd, sysevent_token, fw_id_key, fw_rule_id, sizeof(fw_rule_id));

        if (fw_rule_id[0] != '\0')
        {
            sysevent_set(sysevent_fd, sysevent_token, fw_rule_id, "", 0);
            sysevent_set(sysevent_fd, sysevent_token, fw_id_key, "", 0);
        }

        snprintf(fw_id_key, sizeof(fw_id_key), "dslite_rule_sysevent_id_%u_3", inst);
        memset(fw_rule_id, 0, sizeof(fw_rule_id));
        sysevent_get(sysevent_fd, sysevent_token, fw_id_key, fw_rule_id, sizeof(fw_rule_id));

        if (fw_rule_id[0] != '\0')
        {
            sysevent_set(sysevent_fd, sysevent_token, fw_rule_id, "", 0);
            sysevent_set(sysevent_fd, sysevent_token, fw_id_key, "", 0);
        }

        snprintf(fw_id_key, sizeof(fw_id_key), "dslite_rule_sysevent_id_%u_4", inst);
        memset(fw_rule_id, 0, sizeof(fw_rule_id));
        sysevent_get(sysevent_fd, sysevent_token, fw_id_key, fw_rule_id, sizeof(fw_rule_id));

        if (fw_rule_id[0] != '\0')
        {
            sysevent_set(sysevent_fd, sysevent_token, fw_rule_id, "", 0);
            sysevent_set(sysevent_fd, sysevent_token, fw_id_key, "", 0);
        }
    }

    v_secure_system("sysevent set firewall-restart; conntrack_flush");
    sysevent_set(sysevent_fd, sysevent_token, status_key, "stopped", 0);
    CcspTraceInfo(("%s: Teardown complete for DSLITE inst=%u\n", __FUNCTION__, inst));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS WanMgr_DSLite_Refresh(DML_VIRTUAL_IFACE *pVirtIf)
{
    WanMgr_DSLite_TeardownTunnel(pVirtIf);

    return WanMgr_DSLite_SetupTunnel(pVirtIf);
}
