/***************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2025 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#include <stddef.h>
#include "wifi_hal.h"
#if defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || defined(SCXF10_PORT)
#include "typedefs.h"
#include "bcmwifi_channels.h"
#endif
#include "wifi_hal_priv.h"
#if defined(WLDM_21_2)
#include "wlcsm_lib_api.h"
#else
#include "nvram_api.h"
#endif // defined(WLDM_21_2)
#include "wlcsm_lib_wl.h"
#if defined (ENABLED_EDPD)
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#endif // defined (ENABLED_EDPD)

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXF10_PORT) || defined(RDKB_ONE_WIFI_PROD)
#include <rdk_nl80211_hal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdint.h>
#include <unistd.h>
#elif defined(SCXER10_PORT)
#include <rdk_nl80211_hal.h>
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXF10_PORT || RDKB_ONE_WIFI_PROD

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || \
    defined(TCHCBRV2_PORT) || defined(SKYSR213_PORT) || defined(SCXF10_PORT) || defined(RDKB_ONE_WIFI_PROD)
#undef ENABLE
#undef BW_20MHZ
#undef BW_40MHZ
#undef BW_80MHZ
#undef BW_160MHZ
#undef BW_320MHZ
#define wpa_ptk _wpa_ptk
#define wpa_gtk _wpa_gtk
#define mld_link_info _mld_link_info
#if defined(SCXER10_PORT)
#include <wifi-include/wlioctl.h>
#elif defined(SKYSR213_PORT) || defined(SCXF10_PORT)
#include <wlioctl.h>
#else
#include <wifi/wlioctl.h>
#endif
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXF10_PORT) || defined(RDKB_ONE_WIFI_PROD)

typedef struct sta_list {
    mac_address_t *macs;
    unsigned int num;
} sta_list_t;

static int get_sta_list_handler(struct nl_msg *msg, void *arg)
{
    int rem_mac, i;
    struct nlattr *nlattr;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy sta_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_MAC] = { .type = NLA_BINARY },
        [RDK_VENDOR_ATTR_STA_NUM] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_LIST] = { .type = NLA_NESTED },
    };
    sta_list_t *sta_list = arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_stats_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
        sta_policy) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb_vendor[RDK_VENDOR_ATTR_STA_NUM] == NULL) {
        wifi_hal_stats_error_print("%s:%d STA number data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    sta_list->num = nla_get_u32(tb_vendor[RDK_VENDOR_ATTR_STA_NUM]);
    if (sta_list->num == 0) {
        sta_list->macs = NULL;
        return NL_SKIP;
    }

    sta_list->macs = calloc(sta_list->num, sizeof(mac_address_t));

    if (tb_vendor[RDK_VENDOR_ATTR_STA_LIST] == NULL) {
        wifi_hal_stats_error_print("%s:%d STA list data is missing\n", __func__, __LINE__);
        goto error;
    }

    i = 0;
    nla_for_each_nested(nlattr, tb_vendor[RDK_VENDOR_ATTR_STA_LIST], rem_mac) {
        if (i >= sta_list->num) {
            wifi_hal_stats_error_print("%s:%d STA list overflow\n", __func__, __LINE__);
            goto error;
        }

        if (nla_len(nlattr) != sizeof(mac_address_t)) {
            wifi_hal_stats_error_print("%s:%d Wrong MAC address len\n", __func__, __LINE__);
            goto error;
        }

        memcpy(sta_list->macs[i], nla_data(nlattr), sizeof(mac_address_t));

        i++;
    }

    if (i != sta_list->num) {
        wifi_hal_stats_error_print("%s:%d Failed to receive all stations\n", __func__, __LINE__);
        goto error;
    }

    return NL_SKIP;

error:
    free(sta_list->macs);
    sta_list->macs = NULL;
    sta_list->num = 0;
    return NL_SKIP;
}

static int get_sta_list(wifi_interface_info_t *interface, sta_list_t *sta_list)
{
    int ret;
    struct nl_msg *msg;

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_STATION_LIST);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, get_sta_list_handler, sta_list, NULL, NULL);
    if (ret) {
        wifi_hal_stats_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

static int standard_to_str(uint32_t standard, char *buf, size_t buf_size)
{
    char *std_str;

    switch (standard) {
        case RDK_VENDOR_NL80211_STANDARD_A: std_str = "a"; break;
        case RDK_VENDOR_NL80211_STANDARD_B: std_str = "b"; break;
        case RDK_VENDOR_NL80211_STANDARD_G: std_str = "g"; break;
        case RDK_VENDOR_NL80211_STANDARD_N: std_str = "n"; break;
        case RDK_VENDOR_NL80211_STANDARD_AC: std_str = "ac"; break;
        case RDK_VENDOR_NL80211_STANDARD_AD: std_str = "ad"; break;
        case RDK_VENDOR_NL80211_STANDARD_AX: std_str = "ax"; break;
#ifdef CONFIG_IEEE80211BE
        case RDK_VENDOR_NL80211_STANDARD_BE: std_str = "be"; break;
#endif /* CONFIG_IEEE80211BE */
        default: std_str = ""; break;
    }

    strncpy(buf, std_str, buf_size - 1);

    return 0;
}

static int bw_to_str(uint8_t bw, char *buf, size_t buf_size)
{
    char *bw_str;

    switch (bw) {
        case RDK_VENDOR_NL80211_CHAN_WIDTH_20: bw_str = "20"; break;
        case RDK_VENDOR_NL80211_CHAN_WIDTH_40: bw_str = "40"; break;
        case RDK_VENDOR_NL80211_CHAN_WIDTH_80: bw_str = "80"; break;
        case RDK_VENDOR_NL80211_CHAN_WIDTH_160: bw_str = "160"; break;
#ifdef CONFIG_IEEE80211BE
        case RDK_VENDOR_NL80211_CHAN_WIDTH_320: bw_str = "320"; break;
#endif /* CONFIG_IEEE80211BE */
        default: bw_str = ""; break;
    }

    strncpy(buf, bw_str, buf_size - 1);

    return 0;
}

static int get_sta_stats_handler(struct nl_msg *msg, void *arg)
{
    int i;
    struct nlattr *nlattr;
    struct nl80211_sta_flag_update *sta_flags;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct nlattr *tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy vendor_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_MAC] = { .type = NLA_BINARY, .minlen = ETHER_ADDR_LEN },
        [RDK_VENDOR_ATTR_STA_INFO] = { .type = NLA_NESTED },
    };
    static struct nla_policy sta_info_policy[RDK_VENDOR_ATTR_STA_INFO_MAX + 1] = {
        [RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS] = { .type = NLA_BINARY,
            .minlen = sizeof(struct nl80211_sta_flag_update) },
        [RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_ACTIVE] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_STA_INFO_SNR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES] = {.type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS] = {. type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_MLD_MAC] = {.type = NLA_BINARY, .minlen = ETHER_ADDR_LEN},
        [RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB] = {.type = NLA_U8},
    };
    wifi_associated_dev3_t *stats = arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_stats_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
        vendor_policy) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    for (i = 0; i <= RDK_VENDOR_ATTR_MAX; i++) {
        if (vendor_policy[i].type != 0 && tb_vendor[i] == NULL) {
            wifi_hal_stats_error_print("%s:%d Vendor attribute %d is missing\n", __func__,
                __LINE__, i);
            return NL_SKIP;
        }
    }

    memcpy(stats->cli_MACAddress, nla_data(tb_vendor[RDK_VENDOR_ATTR_MAC]),
        nla_len(tb_vendor[RDK_VENDOR_ATTR_MAC]));

    if (nla_parse_nested(tb_sta_info, RDK_VENDOR_ATTR_STA_INFO_MAX,
        tb_vendor[RDK_VENDOR_ATTR_STA_INFO], sta_info_policy)) {
        wifi_hal_stats_error_print("%s:%d Failed to parse sta info attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS]) {
        sta_flags = nla_data(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS]);
        stats->cli_AuthenticationState = sta_flags->mask & (1 << NL80211_STA_FLAG_AUTHORIZED) &&
            sta_flags->set & (1 << NL80211_STA_FLAG_AUTHORIZED);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST]) {
        stats->cli_LastDataUplinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST]) {
        stats->cli_LastDataDownlinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG]) {
        stats->cli_RSSI = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG]);
        stats->cli_SignalStrength = stats->cli_RSSI;
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN]) {
        stats->cli_MinRSSI = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX]) {
        stats->cli_MaxRSSI = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT]) {
        stats->cli_Retransmissions =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ACTIVE]) {
        stats->cli_Active = nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ACTIVE]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD]) {
        standard_to_str(nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD]),
            stats->cli_OperatingStandard, sizeof(stats->cli_OperatingStandard));
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW]) {
        bw_to_str(nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW]),
            stats->cli_OperatingChannelBandwidth, sizeof(stats->cli_OperatingChannelBandwidth));
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SNR]) {
        stats->cli_SNR = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SNR]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK]) {
        stats->cli_DataFramesSentAck =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK]) {
        stats->cli_DataFramesSentNoAck =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64]) {
        stats->cli_BytesSent = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64]) {
        stats->cli_BytesReceived = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_AUTH_FAILS]) {
        stats->cli_AuthenticationFailures =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_AUTH_FAILS]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM]) {
        stats->cli_Associations = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64]) {
        stats->cli_PacketsSent = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64]) {
        stats->cli_PacketsReceived =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS]) {
        stats->cli_ErrorsSent =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT]) {
        stats->cli_RetransCount =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES]) {
        stats->cli_FailedRetransCount =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES]) {
        stats->cli_RetryCount = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES]) {
        stats->cli_MultipleRetryCount =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX]) {
        stats->cli_MaxDownlinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX]) {
        stats->cli_MaxUplinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM]) {
        stats->cli_activeNumSpatialStreams =
            nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES]) {
        stats->cli_TxFrames = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES]) {
        stats->cli_RxRetries = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS]) {
        stats->cli_RxErrors = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS]);
    }

    if(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB]) {
        stats->cli_MLDEnable = nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB]);
    } else {
        stats->cli_MLDEnable = 0;
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_MAC]) {
        memcpy(stats->cli_MLDAddr, nla_data(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_MAC]),
               nla_len(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_MAC]));
    } else {
        memset(stats->cli_MLDAddr, 0, sizeof(stats->cli_MLDAddr));
    }

    wifi_hal_stats_dbg_print("%s:%d cli_DataFramesSentAck: %lu cli_DataFramesSentNoAck: %lu cli_PacketsSent: %lu cli_BytesSent: %lu\n", __func__, __LINE__, 
            stats->cli_DataFramesSentAck, stats->cli_DataFramesSentNoAck,
           stats->cli_PacketsSent, stats->cli_BytesSent);

    /*
     * Assume the default packet size for wifi blaster is 1470
     * Sometimes when the AP is just up, the cli_BytesSent
     * is very low as just a couple of frames have been sent and not real data.
     * In this case (cli_BytesSent / WIFI_BLASTER_DEFAULT_PKTSIZE)
     * will be 1 or 2 or another low value which is in fact lower than
     * cli_PacketsSent.
     */

    stats->cli_DataFramesSentNoAck = stats->cli_FailedRetransCount;
    if (((stats->cli_BytesSent / WIFI_BLASTER_DEFAULT_PKTSIZE) < stats->cli_PacketsSent)) {
        stats->cli_DataFramesSentAck = stats->cli_PacketsSent - stats->cli_DataFramesSentNoAck;
    } else {
        stats->cli_DataFramesSentAck = (stats->cli_BytesSent / WIFI_BLASTER_DEFAULT_PKTSIZE) -
                          stats->cli_DataFramesSentNoAck;
    }
    stats->cli_PacketsSent = stats->cli_DataFramesSentAck + stats->cli_DataFramesSentNoAck;

    wifi_hal_stats_dbg_print("%s:%d cli_DataFramesSentAck: %lu cli_DataFramesSentNoAck: %lu cli_PacketsSent: %lu cli_BytesSent: %lu\n", __func__, __LINE__, 
            stats->cli_DataFramesSentAck, stats->cli_DataFramesSentNoAck,
            stats->cli_PacketsSent, stats->cli_BytesSent);

    return NL_SKIP;
}

static int get_sta_stats(wifi_interface_info_t *interface, mac_address_t mac,
    wifi_associated_dev3_t *stats)
{
    struct nl_msg *msg;
    struct nlattr *nlattr;
    int ret = RETURN_ERR;

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_STATION);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    nlattr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (nla_put(msg, RDK_VENDOR_ATTR_MAC, ETHER_ADDR_LEN, mac) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to put mac address\n", __func__, __LINE__);
        nlmsg_free(msg);
        return RETURN_ERR;
    }
    nla_nest_end(msg, nlattr);

    ret = nl80211_send_and_recv(msg, get_sta_stats_handler, stats, NULL, NULL);
    if (ret) {
        wifi_hal_stats_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return ret;
}

INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex,
    wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    int ret;
    unsigned int i;
    sta_list_t sta_list = {};
    wifi_interface_info_t *interface;

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to get interface for index %d\n", __func__, __LINE__,
            apIndex);
        return RETURN_ERR;
    }

    ret = get_sta_list(interface, &sta_list);
    if (ret != RETURN_OK) {
        wifi_hal_stats_error_print("%s:%d Failed to get sta list\n", __func__, __LINE__);
        goto exit;
    }

    *associated_dev_array = sta_list.num ?
        calloc(sta_list.num, sizeof(wifi_associated_dev3_t)) : NULL;
    *output_array_size = sta_list.num;

    for (i = 0; i < sta_list.num; i++) {
        ret = get_sta_stats(interface, sta_list.macs[i], &(*associated_dev_array)[i]);
        if (ret != RETURN_OK) {
            wifi_hal_stats_error_print("%s:%d Failed to get sta stats\n", __func__, __LINE__);
            free(*associated_dev_array);
            *associated_dev_array = NULL;
            *output_array_size = 0;
            goto exit;
        }
    }

exit:
    free(sta_list.macs);
    return ret;
}

static int get_channel_stats_handler(struct nl_msg *msg, void *arg)
{
    int i, rem;
    unsigned int freq;
    unsigned char channel;
    struct nlattr *nlattr;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct nlattr *survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_MAX + 1];
    static struct nla_policy vendor_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_SURVEY_INFO] = { .type = NLA_NESTED },
    };
    static struct nla_policy survey_policy[RDK_VENDOR_ATTR_SURVEY_INFO_MAX + 1] = {
        [RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_NOISE] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_RADAR_NOISE] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_MAX_RSSI] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_NON_80211_NOISE] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_CHAN_UTIL] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_ACTIVE] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_TX] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX_SELF] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY] = { .type = NLA_U64 },
    };
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    channel_stats_arr_t *stats = (channel_stats_arr_t *)arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_stats_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
        vendor_policy) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb_vendor[RDK_VENDOR_ATTR_SURVEY_INFO] == NULL) {
        wifi_hal_stats_error_print("%s:%d Survey info attribute is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nla_for_each_nested(nlattr, tb_vendor[RDK_VENDOR_ATTR_SURVEY_INFO], rem) {

        if (nla_parse(survey_info, RDK_VENDOR_ATTR_SURVEY_INFO_MAX, nla_data(nlattr),
            nla_len(nlattr), survey_policy)) {
            wifi_hal_stats_error_print("%s:%d: Failed to parse survey info attibutes\n", __func__,
                __LINE__);
            return NL_SKIP;
        }

        for (i = 0; i <= RDK_VENDOR_ATTR_SURVEY_INFO_MAX; i++) {
            if (survey_policy[i].type != 0 && survey_info[i] == NULL) {
                wifi_hal_stats_error_print("%s:%d Survey info attribute %d is missing\n", __func__,
                    __LINE__, i);
                return NL_SKIP;
            }
        }

        freq = nla_get_u32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY]);
        if (ieee80211_freq_to_chan(freq, &channel) == NUM_HOSTAPD_MODES) {
            wifi_hal_stats_error_print("%s:%d Failed to convert frequency %u to channel\n", __func__,
                __LINE__, freq);
            return NL_SKIP;
        }

        for (i = 0; i < stats->arr_size && stats->arr[i].ch_number != channel; i++);
        if (i == stats->arr_size) {
            continue;
        }

        stats->arr[i].ch_noise =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_NOISE]);
        stats->arr[i].ch_radar_noise =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_RADAR_NOISE]);
        stats->arr[i].ch_max_80211_rssi =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_MAX_RSSI]);
        stats->arr[i].ch_non_80211_noise =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_NON_80211_NOISE]);
        stats->arr[i].ch_utilization =
            nla_get_u8(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_CHAN_UTIL]);
        stats->arr[i].ch_utilization_total =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_ACTIVE]);
        stats->arr[i].ch_utilization_busy =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY]);
        stats->arr[i].ch_utilization_busy_tx =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_TX]);
        stats->arr[i].ch_utilization_busy_rx =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX]);
        stats->arr[i].ch_utilization_busy_self =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX_SELF]);
        stats->arr[i].ch_utilization_busy_ext =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY]);
    }

    return NL_SKIP;
}

static int get_channel_stats(wifi_interface_info_t *interface,
    wifi_channelStats_t *channel_stats_arr, int channel_stats_arr_size)
{
    struct nl_msg *msg;
    int ret = RETURN_ERR;
    channel_stats_arr_t stats = { .arr = channel_stats_arr, .arr_size = channel_stats_arr_size };

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_SURVEY);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, get_channel_stats_handler, &stats, NULL, NULL);
    if (ret) {
        wifi_hal_stats_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array,
    INT array_size)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    wifi_hal_stats_dbg_print("%s:%d: Get radio stats for index: %d\n", __func__, __LINE__,
        radioIndex);

    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to get radio for index: %d\n", __func__, __LINE__,
            radioIndex);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to get interface for radio index: %d\n", __func__,
            __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (get_channel_stats(interface, input_output_channelStats_array, array_size)) {
        wifi_hal_stats_error_print("%s:%d: Failed to get channel stats for radio index: %d\n", __func__,
            __LINE__, radioIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

static int get_radio_diag_handler(struct nl_msg *msg, void *arg)
{
    int i;
    struct nlattr *nlattr;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct nlattr *tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy vendor_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_RADIO_INFO] = { .type = NLA_NESTED },
    };
    static struct nla_policy radio_diag_policy[RDK_VENDOR_ATTR_RADIO_INFO_MAX + 1] = {
        [RDK_VENDOR_ATTR_RADIO_INFO_BYTES_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_BYTES_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PLCP_ERRORS_COUNT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_FCS_ERRORS_COUNT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_INVALID_MAC_COUNT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_OTHER_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_CHANNEL_UTILIZATION] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_ACTIVITY_FACTOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_CARRIERSENSE_THRESHOLD] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_RETRANSMISSION] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_MAX_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_MIN_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_MEDIAN_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_STATS_START_TIME] = { .type = NLA_U64 },
    };
    wifi_radioTrafficStats2_t *radioTrafficStats = arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL) <
        0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_stats_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
            vendor_policy) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    for (i = 0; i <= RDK_VENDOR_ATTR_MAX; i++) {
        if (vendor_policy[i].type != 0 && tb_vendor[i] == NULL) {
            wifi_hal_stats_error_print("%s:%d Vendor attribute %d is missing\n", __func__, __LINE__, i);
            return NL_SKIP;
        }
    }

    if (nla_parse_nested(tb_radio_info, RDK_VENDOR_ATTR_STA_INFO_MAX,
            tb_vendor[RDK_VENDOR_ATTR_RADIO_INFO], radio_diag_policy)) {
        wifi_hal_stats_error_print("%s:%d Failed to parse radio info attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    for (i = 0; i <= RDK_VENDOR_ATTR_RADIO_INFO_MAX; i++) {
        if (radio_diag_policy[i].type != 0 && tb_radio_info[i] == NULL) {
            wifi_hal_stats_error_print("%s:%d radio info attribute %d is missing\n", __func__, __LINE__,
                i);
            return NL_SKIP;
        }
    }

    radioTrafficStats->radio_BytesSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_BYTES_SENT]);
    radioTrafficStats->radio_BytesReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_BYTES_RECEIVED]);
    radioTrafficStats->radio_PacketsSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_SENT]);
    radioTrafficStats->radio_PacketsReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_RECEIVED]);
    radioTrafficStats->radio_ErrorsSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_SENT]);
    radioTrafficStats->radio_ErrorsReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_RECEIVED]);
    radioTrafficStats->radio_DiscardPacketsSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_SENT]);
    radioTrafficStats->radio_DiscardPacketsReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_RECEIVED]);
    radioTrafficStats->radio_PLCPErrorCount = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PLCP_ERRORS_COUNT]);
    radioTrafficStats->radio_FCSErrorCount = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_FCS_ERRORS_COUNT]);
    radioTrafficStats->radio_InvalidMACCount = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_INVALID_MAC_COUNT]);
    radioTrafficStats->radio_PacketsOtherReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_OTHER_RECEIVED]);
    radioTrafficStats->radio_NoiseFloor = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_NOISE_FLOOR]);
    radioTrafficStats->radio_ChannelUtilization = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_CHANNEL_UTILIZATION]);
    radioTrafficStats->radio_ActivityFactor = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_ACTIVITY_FACTOR]);
    radioTrafficStats->radio_CarrierSenseThreshold_Exceeded = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_CARRIERSENSE_THRESHOLD]);
    radioTrafficStats->radio_RetransmissionMetirc = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_RETRANSMISSION]);
    radioTrafficStats->radio_MaximumNoiseFloorOnChannel = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MAX_NOISE_FLOOR]);
    radioTrafficStats->radio_MinimumNoiseFloorOnChannel = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MIN_NOISE_FLOOR]);
    radioTrafficStats->radio_MedianNoiseFloorOnChannel = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MEDIAN_NOISE_FLOOR]);
    radioTrafficStats->radio_StatisticsStartTime = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_STATS_START_TIME]);

    wifi_hal_stats_dbg_print(
        "%s:%d radio_BytesSent %lu radio_BytesReceived %lu radio_PacketsSent %lu "
        "radio_PacketsReceived %lu radio_ErrorsSent %lu radio_ErrorsReceived %lu "
        "radio_DiscardPacketsSent %lu radio_DiscardPacketsReceived %lu radio_PLCPErrorCount %lu "
        "radio_FCSErrorCount %lu radio_InvalidMACCount %lu radio_PacketsOtherReceived %lu "
        "radio_NoiseFloor %d radio_ChannelUtilization %lu radio_ActivityFactor %d "
        "radio_CarrierSenseThreshold_Exceeded %d radio_RetransmissionMetirc %d, "
        "radio_MaximumNoiseFloorOnChannel %d radio_MinimumNoiseFloorOnChannel %d "
        "radio_MedianNoiseFloorOnChannel %d radio_StatisticsStartTime %lu",
        __func__, __LINE__, radioTrafficStats->radio_BytesSent,
        radioTrafficStats->radio_BytesReceived, radioTrafficStats->radio_PacketsSent,
        radioTrafficStats->radio_PacketsReceived, radioTrafficStats->radio_ErrorsSent,
        radioTrafficStats->radio_ErrorsReceived, radioTrafficStats->radio_DiscardPacketsSent,
        radioTrafficStats->radio_DiscardPacketsReceived, radioTrafficStats->radio_PLCPErrorCount,
        radioTrafficStats->radio_FCSErrorCount, radioTrafficStats->radio_InvalidMACCount,
        radioTrafficStats->radio_PacketsOtherReceived, radioTrafficStats->radio_NoiseFloor,
        radioTrafficStats->radio_ChannelUtilization, radioTrafficStats->radio_ActivityFactor,
        radioTrafficStats->radio_CarrierSenseThreshold_Exceeded,
        radioTrafficStats->radio_RetransmissionMetirc,
        radioTrafficStats->radio_MaximumNoiseFloorOnChannel,
        radioTrafficStats->radio_MinimumNoiseFloorOnChannel,
        radioTrafficStats->radio_MedianNoiseFloorOnChannel,
        radioTrafficStats->radio_StatisticsStartTime);
    return NL_SKIP;
}

static int get_radio_diagnostics(wifi_interface_info_t *interface,
    wifi_radioTrafficStats2_t *radioTrafficStats)
{
    struct nl_msg *msg;
    int ret = RETURN_ERR;

    wifi_hal_stats_dbg_print("%s:%d Entering\n", __func__, __LINE__);
    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_RADIO_INFO);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    ret = nl80211_send_and_recv(msg, get_radio_diag_handler, radioTrafficStats, NULL, NULL);
    if (ret) {
        wifi_hal_stats_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *radioTrafficStats)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    wifi_hal_stats_dbg_print("%s:%d: Get radio traffic stats for index: %d\n", __func__, __LINE__,
        radioIndex);

    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to get radio for index: %d\n", __func__, __LINE__,
            radioIndex);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to get interface for radio index: %d\n", __func__,
            __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (get_radio_diagnostics(interface, radioTrafficStats)) {
        wifi_hal_stats_error_print("%s:%d: Failed to get radio diagnostics stats for radio index: %d\n",
            __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

static int set_ap_pwr(wifi_interface_info_t *interface, INT *power)
{
    struct nlattr *nlattr;
    struct nl_msg *msg;
    int ret = RETURN_ERR;

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0,
                                     OUI_COMCAST,
                                     RDK_VENDOR_NL80211_SUBCMD_SET_MGT_FRAME_PWR);

    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    nlattr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

    if (nla_put(msg, RDK_VENDOR_ATTR_MGT_FRAME_PWR_LEVEL, sizeof(*power), power) < 0) {
        wifi_hal_error_print("%s:%d Failed to put AP power\n", __func__, __LINE__);
        nlmsg_free(msg);
        return RETURN_ERR;
    }
    nla_nest_end(msg, nlattr);

    ret = nl80211_send_and_recv(msg, NULL, power, NULL, NULL);

    if (ret) {
        wifi_hal_error_print("%s:%d Failed to send NL message: %d (%s)\n", __func__, __LINE__, ret, strerror(-ret));
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_setApManagementFramePowerControl(INT apIndex, INT dBm)
{
    wifi_interface_info_t *interface;

    wifi_hal_dbg_print("%s:%d: Set AP management frame for index: %d\n", __func__, __LINE__,
        apIndex);

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get interface for ap index: %d\n", __func__,
            __LINE__, apIndex);
        return RETURN_ERR;
    }
    if (set_ap_pwr(interface, &dBm)) {
        wifi_hal_error_print("%s:%d: Failed to set ap power for ap index: %d\n", __func__,
            __LINE__, apIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *tx_power)
{
    return wifi_hal_getRadioTransmitPower(radioIndex, tx_power);
}

    defined(TCHCBRV2_PORT) || defined(SKYSR213_PORT) || defined(SCXF10_PORT) || defined(RDKB_ONE_WIFI_PROD)

static int get_rates(char *ifname, int *rates, size_t rates_size, unsigned int *num_rates)
{
    wl_rateset_t rs;

    if (wl_ioctl(ifname, WLC_GET_CURR_RATESET, &rs, sizeof(wl_rateset_t)) < 0) {
        wifi_hal_error_print("%s:%d: failed to get rateset for %s, err %d (%s)\n", __func__,
            __LINE__, ifname, errno, strerror(errno));
        return RETURN_ERR;
    }

    if (rates_size < rs.count) {
        wifi_hal_error_print("%s:%d: rates size %zu is less than %u\n", __func__, __LINE__,
            rates_size, rs.count);
        rs.count = rates_size;
    }

    for (unsigned int i = 0; i < rs.count; i++) {
        // clear basic rate flag and convert 500 kbps to 100 kbps units
        rates[i] = (rs.rates[i] & 0x7f) * 5;
    }
    *num_rates = rs.count;

    return RETURN_OK;
}

static void platform_get_radio_caps_common(wifi_radio_info_t *radio,
    wifi_interface_info_t *interface)
{
    unsigned int num_rates;
    int rates[WL_MAXRATES_IN_SET];
    struct hostapd_iface *iface = &interface->u.ap.iface;

    if (get_rates(interface->name, rates, ARRAY_SZ(rates), &num_rates) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: failed to get rates for %s\n", __func__, __LINE__,
            interface->name);
        return;
    }

    for (int i = 0; i < iface->num_hw_features; i++) {
        if (iface->hw_features[i].num_rates >= num_rates) {
            memcpy(iface->hw_features[i].rates, rates, num_rates * sizeof(rates[0]));
            iface->hw_features[i].num_rates = num_rates;
        }
    }
}

static void platform_get_radio_caps_2g(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    // Set values from driver beacon, NL values are not valid.
#if defined(XB10_PORT) || defined(SCXER10_PORT) || defined(SCXF10_PORT)
    // SCS bit is not set in driver
    static const u8 ext_cap[] = { 0x85, 0x00, 0x08, 0x02, 0x01, 0x00, 0x40, 0x40, 0x00, 0x40,
        0x20 };
#endif // XB10_PORT || SCXER10_PORT || SCXF10_PORT
#if defined(TCHCBRV2_PORT)
    static const u8 ext_cap[] = { 0x85, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x40, 0x00, 0x00,
        0x20 };
#endif // TCHCBRV2_PORT
#if defined(SKYSR213_PORT)
    static const u8 ext_cap[] = { 0x85, 0x00, 0x08, 0x82, 0x01, 0x00, 0x40, 0x40, 0x00, 0x40,
        0x20 };
#endif // SKYSR213_PORT
    static const u8 ht_mcs[16] = { 0xff, 0xff, 0xff, 0xff };
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || \
    defined(SKYSR213_PORT) || defined(SCXF10_PORT)
    static const u8 he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = { 0x05, 0x00, 0x18, 0x12, 0x00, 0x10 };
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT || SKYSR213_PORT
#if defined(TCHCBRV2_PORT)
    static const u8 he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = { 0x01, 0x00, 0x08, 0x12, 0x00, 0x10 };
#endif // TCHCBRV2_PORT
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || \
    defined(TCHCBRV2_PORT) || defined(SKYSR213_PORT) || defined(SCXF10_PORT)
    static const u8 he_mcs[HE_MAX_MCS_CAPAB_SIZE] = { 0xaa, 0xff, 0xaa, 0xff };
    static const u8 he_ppet[HE_MAX_PPET_CAPAB_SIZE] = { 0x1b, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71 };
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT || TCHCBRV2_PORT || SKYSR213_PORT
#if defined(TCXB7_PORT) || defined(TCHCBRV2_PORT) || defined(SKYSR213_PORT)
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x22, 0x20, 0x02, 0xc0, 0x0f, 0x03, 0x95,
        0x18, 0x00, 0xcc, 0x00 };
#endif // TCXB7_PORT || TCHCBRV2_PORT || SKYSR213_PORT
#if defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || defined(SCXF10_PORT)
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x22, 0x20, 0x02, 0xc0, 0x02, 0x03, 0x95,
        0x00, 0x00, 0xcc, 0x00 };
#endif // TCXB8_PORT || XB10_PORT || SCXER10_PORT || SCXF10_PORT
#if HOSTAPD_VERSION >= 211
    static const u8 eht_mcs[] = { 0x44, 0x44, 0x44 };
#endif /* HOSTAPD_VERSION >= 211 */
    struct hostapd_iface *iface = &interface->u.ap.iface;

    radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_AP_UAPSD;

#if defined(XB10_PORT) || defined(SCXER10_PORT) || defined(TCHCBRV2_PORT) || defined(SKYSR213_PORT) || \
    defined(SCXF10_PORT)
    free(radio->driver_data.extended_capa);
    radio->driver_data.extended_capa = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa, ext_cap, sizeof(ext_cap));
    free(radio->driver_data.extended_capa_mask);
    radio->driver_data.extended_capa_mask = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa_mask, ext_cap, sizeof(ext_cap));
    radio->driver_data.extended_capa_len = sizeof(ext_cap);
#endif // XB10_PORT || SCXER10_PORT || TCHCBRV2_PORT || SKYSR213_PORT || SCXF10_PORT

// To reset the bss transition bit under extended capabilities, since its based on 2GHz vap configuration from OneWiFi.
    if (radio->driver_data.extended_capa_len) {
        radio->driver_data.extended_capa_mask[2] &= 0xF7;
        radio->driver_data.extended_capa[2] &= 0xF7;
    }
    for (int i = 0; i < iface->num_hw_features; i++) {
#if defined(XB10_PORT) || defined(SCXER10_PORT) || defined(SCXF10_PORT)
        iface->hw_features[i].ht_capab = 0x19ef;
#else
        iface->hw_features[i].ht_capab = 0x11ef;
#endif // XB10_PORT || SCXER10_PORT
        iface->hw_features[i].a_mpdu_params &= ~(0x07 << 2);
        iface->hw_features[i].a_mpdu_params |= 0x05 << 2;
        memcpy(iface->hw_features[i].mcs_set, ht_mcs, sizeof(ht_mcs));
#if HOSTAPD_VERSION >= 211
        memcpy(iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].mcs, eht_mcs, sizeof(eht_mcs));
#endif /* HOSTAPD_VERSION >= 211 */

// XER-10 uses old kernel that does not support EHT cap NL parameters
#if defined(SCXER10_PORT)
        iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].eht_supported = true;
        iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].mac_cap = 0x0082;
        memcpy(iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].phy_cap, eht_phy_cap,
            sizeof(eht_phy_cap));
#endif // SCXER10_PORT

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || \
    defined(TCHCBRV2_PORT) || defined(SKYSR213_PORT) || defined(SCXF10_PORT)
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mac_cap, he_mac_cap,
            sizeof(he_mac_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].phy_cap, he_phy_cap,
            sizeof(he_phy_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mcs, he_mcs, sizeof(he_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].ppet, he_ppet, sizeof(he_ppet));
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT || TCHCBRV2_PORT || SKYSR213_PORT || SCXF10_PORT

        for (int ch = 0; ch < iface->hw_features[i].num_channels; ch++) {
            iface->hw_features[i].channels[ch].max_tx_power = 30; // dBm
        }
    }
}

static void platform_get_radio_caps_5g(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
#if defined(XB10_PORT) || defined(SCXER10_PORT) || defined(SCXF10_PORT)
    static const u8 ext_cap[] = { 0x84, 0x00, 0x08, 0x02, 0x01, 0x00, 0x40, 0x40, 0x00, 0x40,
        0x20 };
#endif // XB10_PORT || SCXER10_PORT || SCXF10_PORT
#if defined(TCHCBRV2_PORT)
    static const u8 ext_cap[] = { 0x84, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x40, 0x00, 0x40,
        0x20 };
#endif // TCHCBRV2_PORT
#if defined(SKYSR213_PORT)
    static const u8 ext_cap[] = { 0x84, 0x00, 0x08, 0x82, 0x01, 0x00, 0x40, 0x40, 0x00, 0x40,
        0x20 };
#endif // SKYSR213_PORT
    static const u8 ht_mcs[16] = { 0xff, 0xff, 0xff, 0xff };
    static const u8 vht_mcs[8] = { 0xaa, 0xff, 0x00, 0x00, 0xaa, 0xff, 0x00, 0x20 };
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || \
    defined(TCHCBRV2_PORT) || defined(SKYSR213_PORT) || defined(SCXF10_PORT)
    static const u8 he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = { 0x05, 0x00, 0x18, 0x12, 0x00, 0x10 };
    static const u8 he_mcs[HE_MAX_MCS_CAPAB_SIZE] = { 0xaa, 0xff, 0xaa, 0xff, 0xaa, 0xff, 0xaa,
        0xff };
    static const u8 he_ppet[HE_MAX_PPET_CAPAB_SIZE] = { 0x7b, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71,
        0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71 };
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT || TCHCBRV2_PORT || SKYSR213_PORT || SCXF10_PORT
#if defined(TCXB7_PORT) || defined(TCHCBRV2_PORT) || defined(SKYSR213_PORT)
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x4c, 0x20, 0x02, 0xc0, 0x6f, 0x1b, 0x95,
        0x18, 0x00, 0xcc, 0x00 };
#endif // TCXB7_PORT || TCHCBRV2_PORT || SKYSR213_PORT
#if defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || defined(SCXF10_PORT)
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x4c, 0x20, 0x02, 0xc0, 0x02, 0x1b, 0x95,
        0x00, 0x00, 0xcc, 0x00 };
#endif // TCXB8_PORT || SCXER10_PORT || SCXF10_PORT
#if defined(SCXER10_PORT)
    static const u8 eht_phy_cap[EHT_PHY_CAPAB_LEN] = { 0x2c, 0x00, 0x1b, 0xe0, 0x00, 0xe7, 0x00,
        0x7e, 0x00 };
#endif // SCXER10_PORT
#if HOSTAPD_VERSION >= 211
    static const u8 eht_mcs[] = { 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 };
#endif /* HOSTAPD_VERSION >= 211 */
    struct hostapd_iface *iface = &interface->u.ap.iface;

    radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_AP_UAPSD | WPA_DRIVER_FLAGS_DFS_OFFLOAD;

#if defined(XB10_PORT) || defined(SCXER10_PORT) || defined(TCHCBRV2_PORT) || defined(SKYSR213_PORT) || \
    defined(SCXF10_PORT)
    free(radio->driver_data.extended_capa);
    radio->driver_data.extended_capa = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa, ext_cap, sizeof(ext_cap));
    free(radio->driver_data.extended_capa_mask);
    radio->driver_data.extended_capa_mask = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa_mask, ext_cap, sizeof(ext_cap));
    radio->driver_data.extended_capa_len = sizeof(ext_cap);
#endif // XB10_PORT || SCXER10_PORT || TCHCBRV2_PORT || SKYSR213_PORT

// To reset the bss transition bit under extended capabilities, since its based on 5GHz vap configuration from OneWiFi.
    if (radio->driver_data.extended_capa_len) {
        radio->driver_data.extended_capa_mask[2] &= 0xF7;
        radio->driver_data.extended_capa[2] &= 0xF7;
    }
    for (int i = 0; i < iface->num_hw_features; i++) {
#if defined(XB10_PORT) || defined(SCXER10_PORT) || defined(SCXF10_PORT)
        iface->hw_features[i].ht_capab = 0x09ef;
#else
        iface->hw_features[i].ht_capab = 0x01ef;
#endif // XB10_PORT || SCXER10_PORT || SCXF10_PORT
        iface->hw_features[i].a_mpdu_params &= ~(0x07 << 2);
        iface->hw_features[i].a_mpdu_params |= 0x05 << 2;
        memcpy(iface->hw_features[i].mcs_set, ht_mcs, sizeof(ht_mcs));
#if defined(TCXB7_PORT) || defined(TCHCBRV2_PORT)
        iface->hw_features[i].vht_capab = 0x0f8b69b5;
#else
        iface->hw_features[i].vht_capab = 0x0f8b69b6;
#endif
        memcpy(iface->hw_features[i].vht_mcs_set, vht_mcs, sizeof(vht_mcs));

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || \
    defined(TCHCBRV2_PORT) || defined(SKYSR213_PORT) || defined(SCXF10_PORT)
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mac_cap, he_mac_cap,
            sizeof(he_mac_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].phy_cap, he_phy_cap,
            sizeof(he_phy_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mcs, he_mcs, sizeof(he_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].ppet, he_ppet, sizeof(he_ppet));
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT || TCHCBRV2_PORT || SKYSR213_PORT || SCXF10_PORT

// XER-10 uses old kernel that does not support EHT cap NL parameters
#if defined(SCXER10_PORT)
        iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].eht_supported = true;
        iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].mac_cap = 0x00c2;
        memcpy(iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].phy_cap, eht_phy_cap,
            sizeof(eht_phy_cap));
#endif // SCXER10_PORT
#if HOSTAPD_VERSION >= 211
        memcpy(iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].mcs, eht_mcs, sizeof(eht_mcs));
#endif /* HOSTAPD_VERSION >= 211 */

        for (int ch = 0; ch < iface->hw_features[i].num_channels; ch++) {
            if (iface->hw_features[i].channels[ch].flag & HOSTAPD_CHAN_RADAR) {
                iface->hw_features[i].channels[ch].max_tx_power = 24; // dBm
            } else {
                iface->hw_features[i].channels[ch].max_tx_power = 30; // dBm
            }

            /* Re-enable DFS channels disabled due to missing WPA_DRIVER_FLAGS_DFS_OFFLOAD flag */
            if (iface->hw_features[i].channels[ch].flag & HOSTAPD_CHAN_DISABLED &&
                iface->hw_features[i].channels[ch].flag & HOSTAPD_CHAN_RADAR) {
                iface->hw_features[i].channels[ch].flag &= ~HOSTAPD_CHAN_DISABLED;
            }
        }
    }
}

static void platform_get_radio_caps_6g(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
#if defined(XB10_PORT) || defined(SCXER10_PORT) || defined(SCXF10_PORT)
    static const u8 ext_cap[] = { 0x84, 0x00, 0x48, 0x02, 0x01, 0x00, 0x40, 0x40, 0x00, 0x40,
        0x21 };
#endif // XB10_PORT || SCXER10_PORT || SCXF10_PORT
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || \
    defined(SCXF10_PORT)
    static const u8 he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = { 0x05, 0x00, 0x18, 0x12, 0x00, 0x10 };
#if defined(XB10_PORT)
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x4c, 0x20, 0x42, 0xc0, 0x02, 0x1b, 0x95,
        0x00, 0x00, 0xcc, 0x00 };
#else
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x4c, 0x20, 0x02, 0xc0, 0x02, 0x1b, 0x95,
        0x00, 0x00, 0xcc, 0x00 };
#endif
    static const u8 he_mcs[HE_MAX_MCS_CAPAB_SIZE] = { 0xaa, 0xff, 0xaa, 0xff, 0xaa, 0xff, 0xaa,
        0xff };
    static const u8 he_ppet[HE_MAX_PPET_CAPAB_SIZE] = { 0x7b, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71,
        0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71 };
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT || SCXF10_PORT
#if defined(SCXER10_PORT)
    static const u8 eht_phy_cap[EHT_PHY_CAPAB_LEN] = { 0x2e, 0x00, 0x00, 0x60, 0x00, 0xe7, 0x00,
        0x0e, 0x00 };
#endif // SCXER10_PORT
#if HOSTAPD_VERSION >= 211
    static const u8 eht_mcs[] = { 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 };
#endif /* HOSTAPD_VERSION >= 211 */
    struct hostapd_iface *iface = &interface->u.ap.iface;

#if defined(XB10_PORT) || defined(SCXER10_PORT) || defined(SCXF10_PORT)
    free(radio->driver_data.extended_capa);
    radio->driver_data.extended_capa = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa, ext_cap, sizeof(ext_cap));
    free(radio->driver_data.extended_capa_mask);
    radio->driver_data.extended_capa_mask = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa_mask, ext_cap, sizeof(ext_cap));
    radio->driver_data.extended_capa_len = sizeof(ext_cap);
#endif // XB10_PORT || SCXER10_PORT || SCXF10_PORT

// To reset the bss transition bit under extended capabilities, since its based on 6GHz vap configuration from OneWiFi.
    if (radio->driver_data.extended_capa_len) {
        radio->driver_data.extended_capa_mask[2] &= 0xF7;
        radio->driver_data.extended_capa[2] &= 0xF7;
    }
    for (int i = 0; i < iface->num_hw_features; i++) {
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || \
    defined(SCXF10_PORT)
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mac_cap, he_mac_cap,
            sizeof(he_mac_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].phy_cap, he_phy_cap,
            sizeof(he_phy_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mcs, he_mcs, sizeof(he_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].ppet, he_ppet, sizeof(he_ppet));
        iface->hw_features[i].he_capab[IEEE80211_MODE_AP].he_6ghz_capa = 0x06bd;
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT

// XER-10 uses old kernel that does not support EHT cap NL parameters
#if defined(SCXER10_PORT)
        iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].eht_supported = true;
        iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].mac_cap = 0x00c2;
        memcpy(iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].phy_cap, eht_phy_cap,
            sizeof(eht_phy_cap));
#endif // SCXER10_PORT
#if HOSTAPD_VERSION >= 211
        memcpy(iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].mcs, eht_mcs, sizeof(eht_mcs));
#endif /* HOSTAPD_VERSION >= 211 */

        for (int ch = 0; ch < iface->hw_features[i].num_channels; ch++) {
            iface->hw_features[i].channels[ch].max_tx_power = 30; // dBm
        }
    }
}

int platform_get_radio_caps(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed to get radio for index: %d\n", __func__, __LINE__,
            index);
        return RETURN_ERR;
    }

#ifdef CONFIG_IEEE80211BE
        radio->driver_data.capa.flags2 |= WPA_DRIVER_FLAGS2_MLO;

        /*
         * FIXME: Hardcodes eml_capa and mld_capa_and_ops because brcm does not provide
         * this information and we have errors in hostap.
         *
         * Remove it when brcm makes the necessary changes.
         */
        radio->driver_data.iface_ext_capa[NL80211_IFTYPE_UNSPECIFIED].eml_capa =
            (((8 << 11) & EHT_ML_EML_CAPA_TRANSITION_TIMEOUT_MASK) |
                ((0 << 8) & EHT_ML_EML_CAPA_EMLMR_DELAY_MASK) |
                ((0 << 7) & EHT_ML_EML_CAPA_EMLMR_SUPP) |
                ((0 << 4) & EHT_ML_EML_CAPA_EMLSR_TRANS_DELAY_MASK) |
                (((0 << 1) & EHT_ML_EML_CAPA_EMLSR_PADDING_DELAY_MASK) |
                    ((1 << 0) & EHT_ML_EML_CAPA_EMLSR_SUPP)));

        radio->driver_data.iface_ext_capa[NL80211_IFTYPE_UNSPECIFIED].mld_capa_and_ops =
            ((0 << 12 & EHT_ML_MLD_CAPA_AAR_SUPP) |
                ((15 << 7) & EHT_ML_MLD_CAPA_FREQ_SEP_FOR_STR_MASK) |
                (EHT_ML_MLD_CAPA_TID_TO_LINK_MAP_ALL_TO_ALL |
                    EHT_ML_MLD_CAPA_TID_TO_LINK_MAP_ALL_TO_ONE) |
                ((0 << 4) & EHT_ML_MLD_CAPA_SRS_SUPP) |
                ((MAX_NUM_MLD_LINKS - 1) & EHT_ML_MLD_CAPA_MAX_NUM_SIM_LINKS_MASK));
#endif /* CONFIG_IEEE80211BE */

    for (interface = hash_map_get_first(radio->interface_map); interface != NULL;
        interface = hash_map_get_next(radio->interface_map, interface)) {

        if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
            continue;
        }

        platform_get_radio_caps_common(radio, interface);

        if (strstr(interface->vap_info.vap_name, "2g")) {
            platform_get_radio_caps_2g(radio, interface);
        } else if (strstr(interface->vap_info.vap_name, "5g")) {
            platform_get_radio_caps_5g(radio, interface);
        } else if (strstr(interface->vap_info.vap_name, "6g")) {
            platform_get_radio_caps_6g(radio, interface);
        }
    }

    return RETURN_OK;
}

#else

int platform_get_radio_caps(wifi_radio_index_t index)
{
    return RETURN_OK;
}
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT || TCHCBRV2_PORT || SKYSR213_PORT || SCXF10_PORT || RDKB_ONE_WIFI_PROD

int platform_get_reg_domain(wifi_radio_index_t radioIndex, UINT *reg_domain)
{
    return RETURN_OK;
}

#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE)
static bool platform_radio_state(wifi_radio_index_t index)
{
    FILE *fp;
    char radio_state[4] = {'\0'};

    fp = (FILE *)v_secure_popen("r", "wl -i wl%d isup", index);
    if (fp) {
        fgets(radio_state, sizeof(radio_state), fp);
        v_secure_pclose(fp);
    }
    return (radio_state[0] == '1') ? true : false;
}

static bool platform_is_eht_enabled(wifi_radio_index_t index)
{
    FILE *fp;
    char eht[16]={'\0'};

    fp = (FILE *)v_secure_popen("r", "wl -i wl%d eht", index);
    if (fp) {
        fgets(eht, sizeof(eht), fp);
        v_secure_pclose(fp);
    }
    return (eht[0] == '1') ? true : false;
}

static void platform_set_eht_hal_callback(wifi_interface_info_t *interface)
{
    wifi_hal_dbg_print("%s:%d EHT completed for %s\n", __func__, __LINE__, interface->name);
    l_eht_set = true;
}

static void platform_wait_for_eht(void)
{
    int i;

    usleep(200*1000);
    for (i = 0; i < 32; i++) {
        if (l_eht_set) {
            return;
        }
        usleep(25*1000);
    }
    return;
}

static void platform_set_eht(wifi_radio_index_t index, bool enable)
{
    bool eht_enabled;
    bool radio_up;
    int bss;

    eht_enabled = platform_is_eht_enabled(index);
    if (eht_enabled == enable) {
        return;
    }

    radio_up = platform_radio_state(index);
    if (radio_up) {
        v_secure_system("wl -i wl%d down", index);
    }
    v_secure_system("wl -i wl%d eht %d", index, (enable) ? 1 : 0);
    v_secure_system("wl -i wl%d eht bssehtmode %d", index, (enable) ? 1 : 0);
    for (bss = 1; bss <= 7; bss++) {
        v_secure_system("wl -i wl%d.%d eht bssehtmode %d", index, bss, (enable) ? 1 : 0);
    }
    wifi_hal_dbg_print("%s: wl%d eht changed to %d\n", __func__, index, (enable == true) ? 1 : 0);
    if (radio_up) {
        l_eht_set = false;
        g_eht_oneshot_notify = platform_set_eht_hal_callback;
        v_secure_system("wl -i wl%d up", index);
        platform_wait_for_eht();
    }

    g_eht_oneshot_notify = NULL;

    return;
}

int platform_set_amsdu_tid(wifi_interface_info_t *interface, uint8_t *amsdu_tid)
{
    static uint8_t cur_amsdu_tid[MAX_NUM_RADIOS][RDK_VENDOR_NL80211_AMSDU_TID_MAX] = {
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

    int radio_index = interface->vap_info.radio_index;

    for (int index = 0; index < RDK_VENDOR_NL80211_AMSDU_TID_MAX; index++) {
        /* minimize the calling of wl if same value */
        if (cur_amsdu_tid[radio_index][index] != amsdu_tid[index]) {
            v_secure_system("wl -i %s amsdu_tid %d %u", interface->name, index, amsdu_tid[index]);
            cur_amsdu_tid[radio_index][index] = amsdu_tid[index];
            wifi_hal_dbg_print("%s: %s amsdu_tid[%d] = %u\n", __func__, interface->name, index, amsdu_tid[index]);
        }
    }
    return RETURN_OK;
}

#if defined(KERNEL_NO_320MHZ_SUPPORT)
static void platform_get_current_chanspec(char *ifname, char *cur_chanspec, size_t size)
{
     FILE *fp = NULL;

    fp = (FILE *)v_secure_popen("r", "wl -i %s chanspec", ifname);
    if (fp) {
        fgets(cur_chanspec, size, fp);
        cur_chanspec[strlen(cur_chanspec)-1] = '\0';
        v_secure_pclose(fp);
    } else {
        cur_chanspec[0] = '\0';
    }
}

static bool platform_is_same_chanspec(wifi_radio_index_t index, char *new_chanspec)
{
    char cur_chanspec[32] = {'\0'};
    FILE *fp = NULL;

    fp = (FILE *)v_secure_popen("r", "wl -i wl%d chanspec", index);
    if (fp) {
        fgets(cur_chanspec, sizeof(cur_chanspec), fp);
        cur_chanspec[strlen(cur_chanspec)-1] = '\0';
        v_secure_pclose(fp);
    }

    wifi_hal_dbg_print("%s - current wl%d chanspec=%s,  new chanspec=%s\n", __func__, index, cur_chanspec, new_chanspec);
    return (!strncmp(cur_chanspec, new_chanspec, strlen(new_chanspec))) ? true : false;
}

static void platform_csa_to_chanspec(struct csa_settings *settings, char *chspec)
{
    char *band = "";

    if ((settings->freq_params.freq >= MIN_FREQ_MHZ_6G) && (settings->freq_params.freq <= MAX_FREQ_MHZ_6G)) {
        band = "6g";
    }

    if (settings->freq_params.bandwidth == 20) {
        sprintf(chspec, "%s%d", band, settings->freq_params.channel);
    } else if ((settings->freq_params.bandwidth == 40) && (settings->freq_params.freq < MIN_FREQ_MHZ_6G)) {
        sprintf(chspec, "%d%c", settings->freq_params.channel, (settings->freq_params.sec_channel_offset == 1) ? 'l' : 'u');
    } else {
        sprintf(chspec, "%s%d/%d", band, settings->freq_params.channel, settings->freq_params.bandwidth);
    }
}

static enum nl80211_chan_width bandwidth_str_to_nl80211_width(char *bandwidth)
{
    enum nl80211_chan_width width;

    if (!strncmp(bandwidth, "40", 2)) {
        width = NL80211_CHAN_WIDTH_40;
    } else if (!strncmp(bandwidth, "80", 2)) {
        width = NL80211_CHAN_WIDTH_80;
    } else if (!strncmp(bandwidth, "160", 3)) {
        width = NL80211_CHAN_WIDTH_160;
    } else if (!strncmp(bandwidth, "320", 3)) {
        width = NL80211_CHAN_WIDTH_320;
    } else if (strchr(bandwidth, 'l') || strchr(bandwidth, 'u')) {
        width = NL80211_CHAN_WIDTH_40;
    } else {
        width = NL80211_CHAN_WIDTH_20;
    }

    return width;
}

static enum nl80211_chan_width platform_get_chanspec_bandwidth(char *chanspec)
{
    char *bw = NULL;
    char spec[32];
    char *str;
    char *space;
    enum nl80211_chan_width width;

    str = strncpy(spec, chanspec, sizeof(spec));
    space = strrchr(str, ' ');
    if (space) *space = '\0';
    bw = strchr(str, '/');
    if (!strncmp(str, "6g", 2)) {
        if (bw == NULL) {
            width = NL80211_CHAN_WIDTH_20;
        } else {
            width = bandwidth_str_to_nl80211_width(++bw);
        }
    } else if (bw) {
        width = bandwidth_str_to_nl80211_width(++bw);
    } else {
        width = bandwidth_str_to_nl80211_width(str);
    }

    return width;
}

enum nl80211_chan_width platform_get_bandwidth(wifi_interface_info_t *interface)
{
    char chanspec[32];
    int width;

    platform_get_current_chanspec(interface->name, chanspec, sizeof(chanspec));
    width = platform_get_chanspec_bandwidth(chanspec);
    wifi_hal_dbg_print("%s - Interface=%s chanspec=%s width=%d\n", __func__, interface->name, chanspec, width);
    return width;
}

void platform_switch_channel(wifi_interface_info_t *interface, struct csa_settings *settings)
{
    char chanspec[32] = {'\0'};

    wifi_hal_dbg_print("%s - csa: name=%s block=%d cs_count=%d channel=%d bandwidth=%d\n", \
                        __func__, interface->name, settings->block_tx, settings->cs_count, settings->freq_params.channel, settings->freq_params.bandwidth);
    platform_csa_to_chanspec(settings, chanspec);
    wifi_hal_dbg_print("%s - csa settings: wl -i %s csa %d %d %s\n", __func__, interface->name, settings->block_tx, settings->cs_count, chanspec);
    v_secure_system("wl -i %s csa %d %d %s", interface->name, settings->block_tx, settings->cs_count, chanspec);
}

void platform_set_csa(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    char chanspec[32] = {'\0'};

    get_chanspec_string(operationParam, chanspec, index);
    if (platform_is_same_chanspec(index, chanspec) == false) {
        bool bss_up;
        wifi_radio_info_t *radio;
        wifi_interface_info_t *interface;

        radio = get_radio_by_rdk_index(index);
        interface = get_private_vap_interface(radio);
        bss_up = platform_is_bss_up(interface->name);
        if (bss_up == false) {
            wifi_hal_dbg_print("%s - bring %s bss up\n", __func__, interface->name);
            platform_bss_enable(interface->name, true);
        }
        wifi_hal_dbg_print("%s - name=wl%d block=0 cs_count=5 chanspec=%s\n", __func__, index, chanspec);
        v_secure_system("wl -i wl%d csa 0 5 %s", index, chanspec);
    }
}

void platform_set_chanspec(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam, bool b_check_radio)
{
    char new_chanspec[32] = {'\0'};

    /* construct target chanspec */
    get_chanspec_string(operationParam, new_chanspec, index);

    /* compare current cchanspec to target chanspec */
    if (platform_is_same_chanspec(index, new_chanspec) == false) {
        bool b_radio_up = true;

        if (b_check_radio) {
            b_radio_up = platform_radio_state(index);
            if (b_radio_up) {
                v_secure_system("wl -i wl%d down", index);
            }
        }

        wifi_hal_dbg_print("%s: wl%d chanspec %s\n", __func__, index, new_chanspec);
        v_secure_system("wl -i wl%d chanspec %s", index, new_chanspec);
        if (b_check_radio && b_radio_up) {
            v_secure_system("wl -i wl%d up", index);
        }
    }
}

void platform_config_eht_chanspec(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    bool enable;
    bool eht_enabled = false;

    enable = (operationParam->variant & WIFI_80211_VARIANT_BE) ? true : false;
    eht_enabled = platform_is_eht_enabled(index);

    /* no op if no change in eht state */
    if (enable == eht_enabled) {
        wifi_hal_dbg_print("%s - No change EHT=%d\n", __func__, (eht_enabled) ? 1 : 0);
        platform_set_csa(index, operationParam);
    } else {
        bool radio_up = platform_radio_state(index);
        if (radio_up) {
            v_secure_system("wl -i wl%d down", index);
        }
        v_secure_system("wl -i wl%d eht %d", index, (enable) ? 1 : 0);
        wifi_hal_dbg_print("%s: wl%d eht changed to %d\n", __func__, index, (enable == true) ? 1 : 0);
        platform_set_chanspec(index, operationParam, false);
        if (radio_up) {
            v_secure_system("wl -i wl%d up", index);
        }
    }
}

bool platform_is_bss_up(char* ifname)
{
    FILE *fp;
    char bss_state[16]={'\0'};

    fp = (FILE *)v_secure_popen("r", "wl -i %s bss", ifname);
    if (fp) {
        fgets(bss_state, sizeof(bss_state), fp);
        v_secure_pclose(fp);
    }
    return !strncmp(bss_state, "up", 2) ? true : false;
}

void platform_bss_enable(char* ifname, bool enable)
{
    bool bss_enabled = platform_is_bss_up(ifname);

    if (bss_enabled == enable) {
        return;
    }
    if (enable) {
        v_secure_system("wl -i %s bss up", ifname);
    } else {
        v_secure_system("wl -i %s bss down", ifname);
    }
}
#endif
#endif

#ifdef CONFIG_IEEE80211BE

static struct hostapd_mld g_mlo_mld[MLD_UNIT_COUNT] = {0};
static struct hostapd_mld g_slo_mld[MAX_VAP] = {0};

extern void hostapd_bss_link_deinit(struct hostapd_data *hapd);

/*
 * Get MLD entry index.
 *
 * @note This is semantic trick to help distinguish between mld_unit and mld_id because according to
 * the spec MLD_ID has nothing to do with entry id and has its own calculation logic, but in fact in
 * hostapd-2.11 MLD_ID always evaluates to 0 regardless of the actual value of mld_id.
 */
static inline void set_mld_unit(struct hostapd_bss_config *conf, unsigned char mld_unit)
{
    conf->mld_id = mld_unit;
}
/*
 * Set MLD entry index.
 *
 * @note This is semantic trick to help distinguish between mld_unit and mld_id because according to
 * the spec MLD_ID has nothing to do with entry id and has its own calculation logic, but in fact in
 * hostapd-2.11 MLD_ID always evaluates to 0 regardless of the actual value of mld_id.
 */
static inline unsigned char get_mld_unit(struct hostapd_bss_config *conf)
{
    return conf->mld_id;
}

int nl80211_drv_mlo_msg(struct nl_msg *msg, struct nl_msg **msg_mlo, void *priv,
    struct wpa_driver_ap_params *params)
{
    (void)msg;

    *msg_mlo = NULL;

/*
 *  `SERCOMMXER10` does not support the nl mlo vendor commands.
 */
#ifndef SCXER10_PORT
    wifi_interface_info_t *interface;
    struct hostapd_bss_config *conf;
    struct hostapd_data *hapd;
    struct nlattr *nlattr_vendor;
    mac_addr_str_t mld_addr = {};
    unsigned char apply;

    interface = (wifi_interface_info_t *)priv;
    conf = &interface->u.ap.conf;
    hapd = &interface->u.ap.hapd;

    /*
     * NOTE: According to the new updates of the brcm contract of sending the message
     * `RDK_VENDOR_NL80211_SUBCMD_SET_MLD` we can't send this message for config -1 (`link_id=-1`).
     */
    if (!params->mld_ap && (u8)hapd->mld_link_id == (u8)-1) {
        wifi_hal_dbg_print("%s:%d skip Non-MLO iface:%s:\n", __func__, __LINE__, conf->iface);
        return 0;
    }

    // Validation
    if (params->mld_ap) {
        if (get_mld_unit(conf) != (unsigned char)-1 && get_mld_unit(conf) >= RDK_VENDOR_MAX_NUM_MLD_UNIT) {
            wifi_hal_error_print("%s:%d: Invalid mld_id:%u\n", __func__, __LINE__, conf->mld_id);
            return -1;
        }
        if ((u8)params->mld_link_id != (u8)NL80211_DRV_LINK_ID_NA &&
            params->mld_link_id >= RDK_VENDOR_MAX_NUM_MLD_LINKS) {
            wifi_hal_error_print("%s:%d: Invalid mld_link_id:%u\n", __func__, __LINE__,
                params->mld_link_id);
            return -1;
        }

        (void)to_mac_str(hapd->mld->mld_addr, mld_addr);
    }

    /*
     * NOTE: The BRCM driver does not support MLO reconfiguration and even sending the same message
     * to the module twice.
     */
#ifndef CONFIG_NO_MLD_DETECT_DOUBLE_APPLY
    char fname_buff[32 + sizeof("/tmp/.mld_")];
    int fd;
    snprintf(fname_buff, sizeof(fname_buff), "/tmp/.mld_%s", conf->iface);
    if ((fd = open(fname_buff, O_WRONLY | O_CREAT | O_EXCL, 0)) == -1) {
        wifi_hal_dbg_print("%s:%d skip double apply for the iface:%s:\n", __func__, __LINE__,
            conf->iface);
        return 0;
    }
    close(fd);
#endif /* CONFIG_NO_MLD_DOUBLE_APPLY */

    /*
     * !FIXME: need to look for the last active VAP.
     *
     * NOTE: We cannot iterate over `interface_map` because this collection `hash_map t` has a
     * stateful iterator and any call to `hash_map_get_first` under the loop of this collection
     * instance invalidates the top-level iterator.
     */
    apply = is_wifi_hal_6g_radio_from_interfacename(conf->iface);

    wifi_hal_dbg_print(
        "%s:%d iface:%s - mld_ap:%d mld_unit:%u mld_link_id:%u mld_addr:%s apply:%d\n", __func__,
        __LINE__, conf->iface, params->mld_ap, get_mld_unit(conf), params->mld_link_id, mld_addr,
        apply);

    /*
     * message format
     *
     * NL80211_ATTR_VENDOR_DATA
     * RDK_VENDOR_ATTR_MLD_ENABLE
     * RDK_VENDOR_ATTR_MLD_UNIT
     * RDK_VENDOR_ATTR_MLD_LINK_ID
     * RDK_VENDOR_ATTR_MLD_MAC
     * RDK_VENDOR_ATTR_MLD_CONFIG_APPLY
     */
    if ((*msg_mlo = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
             RDK_VENDOR_NL80211_SUBCMD_SET_MLD)) == NULL ||
        (nlattr_vendor = nla_nest_start(*msg_mlo, NL80211_ATTR_VENDOR_DATA)) == NULL ||
        nla_put_u8(*msg_mlo, RDK_VENDOR_ATTR_MLD_ENABLE, params->mld_ap) < 0 ||
        (params->mld_ap ?
                (nla_put_u8(*msg_mlo, RDK_VENDOR_ATTR_MLD_UNIT, get_mld_unit(conf)) < 0 ||
                    nla_put_u8(*msg_mlo, RDK_VENDOR_ATTR_MLD_LINK_ID, params->mld_link_id) < 0 ||
                    (!is_zero_ether_addr(hapd->mld->mld_addr) &&
                        nla_put(*msg_mlo, RDK_VENDOR_ATTR_MLD_MAC, ETH_ALEN, hapd->mld->mld_addr) <
                            0)) :
                0) ||
        nla_put_u8(*msg_mlo, RDK_VENDOR_ATTR_MLD_CONFIG_APPLY, apply) < 0) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        nlmsg_free(*msg_mlo);
        return -1;
    }
    nla_nest_end(*msg_mlo, nlattr_vendor);
#endif /* SCXER10_PORT */

    return 0;
}

int nl80211_send_mlo_msg(struct nl_msg *msg)
{
    return ((msg != NULL) ? nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL) : 0);
}

void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb) {
    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC] &&
        nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]) >= 2) {
        const u8 *pos;

        pos = nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]);
        eht_capab->mac_cap = WPA_GET_LE16(pos);
    }
}

#if 0
/* TODO: temporary solution, mld id should come from vap configuration */
static unsigned char platform_get_mld_unit_for_ap(int ap_index)
{
    unsigned char res;

    if(is_wifi_hal_vap_private(ap_index)) {
        res = 0;
    } else if(is_wifi_hal_vap_xhs(ap_index)) {
        res = 1;
    } else if(is_wifi_hal_vap_hotspot_open(ap_index)) {
        res = 2;
    } else if(is_wifi_hal_vap_lnf_psk(ap_index)) {
        res = 3;
    } else if(is_wifi_hal_vap_hotspot_secure(ap_index)) {
        res = 4;
    } else if(is_wifi_hal_vap_lnf_radius(ap_index)) {
        res = 5;
    } else if(is_wifi_hal_vap_mesh_backhaul(ap_index)) {
        res = 6;
    } else {
        res = 7;
    }

    wifi_hal_dbg_print("%s:%d mld_unit:%u for the ap_index:%d\n", __func__, __LINE__, res, ap_index);
    return res;
}
#endif

/* TODO: temporary solution, link_id should come from vap configuration
 * 2. link_id is already arriving from vap configuration, but the driver still requires a valid NVRAM configuration. */
static unsigned char platform_get_link_id_for_radio_index(unsigned int radio_index, unsigned int ap_index)
{
    int mlo_config[4];
    unsigned char res = NL80211_DRV_LINK_ID_NA;

#ifndef CONFIG_NO_MLD_ONLY_PRIVATE
    if (!is_wifi_hal_vap_private(ap_index)) {
        wifi_hal_dbg_print("%s:%d skip MLO for Non-Private VAP radio_index:%u ap_index:%u\n",
            __func__, __LINE__, radio_index, ap_index);
        radio_index = -1;
    }
#endif /* CONFIG_NO_MLD_ONLY_PRIVATE */

    if (radio_index < (sizeof(mlo_config) / sizeof(*mlo_config))) {
        char *wl_mlo_config;

        wl_mlo_config = nvram_get("wl_mlo_config");
        if (wl_mlo_config != NULL) {
            int ret;

            ret = sscanf(wl_mlo_config, "%d %d %d %d", &mlo_config[0], &mlo_config[1],
                &mlo_config[2], &mlo_config[3]);

            if ((sizeof(mlo_config) / sizeof(*mlo_config)) == ret &&
                mlo_config[radio_index] < (sizeof(mlo_config) / sizeof(*mlo_config)) &&
                mlo_config[radio_index] >= -1) {
                res = (unsigned char)mlo_config[radio_index];
            }
        }
    }

    wifi_hal_dbg_print("%s:%d link_id:%u for the radio_index:%u ap_index:%u\n", __func__, __LINE__,
        res, radio_index, ap_index);
    return res;
}

static unsigned char platform_iface_is_mlo_ap(const char *iface)
{
    char name[32 + sizeof("_bss_mlo_mode")];
    const char *wl_bss_mlo_mode;
    unsigned char res;

    (void)snprintf(name, sizeof(name), "%s_bss_mlo_mode", iface);
    wl_bss_mlo_mode = nvram_get(name);
    res = ((wl_bss_mlo_mode != NULL) ? atoi(wl_bss_mlo_mode) : 0);

    wifi_hal_dbg_print("%s:%d mld_ap:%u for the iface:%s\n", __func__, __LINE__, res, iface);
    return res;
}

static void nvram_update_wl_mlo_apply(const char *iface, unsigned char mlo_apply, int *nvram_changed)
{
    char name[32 + sizeof("_mlo_apply")];
    const char *last_mld_vap = "wl2.4";
    const char *wl_mlo_apply;
    unsigned char res;
    unsigned char is_last_radio = 0;

    is_last_radio = is_wifi_hal_6g_radio_from_interfacename(iface);
    if (!is_last_radio)
        return;

    (void)snprintf(name, sizeof(name), "%s_mlo_apply", last_mld_vap);
    wl_mlo_apply = nvram_get(name);
    res = ((wl_mlo_apply != NULL) ? atoi(wl_mlo_apply) : 0);
    if (res == mlo_apply) {
        return; /* No changes are needed */
    }

    set_decimal_nvram_param(name, mlo_apply);
    *nvram_changed |=1;
    wifi_hal_info_print("%s:%d Updating wl_mlo_apply nvram %s=%u for the iface:%s\n", __func__,
        __LINE__, name, mlo_apply, iface);
}

static void nvram_update_wl_bss_mlo_mode(const char *iface, unsigned char bss_mlo_mode, int *nvram_changed)
{
    char name[32 + sizeof("_bss_mlo_mode")];
    const char *wl_bss_mlo_mode;
    unsigned char res;

    (void)snprintf(name, sizeof(name), "%s_bss_mlo_mode", iface);
    wl_bss_mlo_mode = nvram_get(name);
    res = ((wl_bss_mlo_mode != NULL) ? atoi(wl_bss_mlo_mode) : 0);
    if (res == bss_mlo_mode) {
        return; /* No changes are needed */
    }

    set_decimal_nvram_param(name, bss_mlo_mode);
    *nvram_changed |=1;
    wifi_hal_info_print("%s:%d Updating wl_bss_mlo_mode nvram %s=%u for the iface:%s\n", __func__,
        __LINE__, name, bss_mlo_mode, iface);
}

static void nvram_update_wl_mlo_config(unsigned int radio_index, int mld_link_id, int *nvram_changed)
{
    int mlo_config[4] = { -1, -1, -1, -1 };
    char *wl_mlo_config = NULL;
    char new_nvram_val[BUF_SIZE];

    if (radio_index >= (sizeof(mlo_config) / sizeof(*mlo_config))) {
        wifi_hal_error_print("%s:%d: radio_index:%d out of range (max radio_index: %lu)!\n",
            __func__, __LINE__, radio_index, (sizeof(mlo_config) / sizeof(*mlo_config)) - 1);
        return;
    }
    if ((u8)mld_link_id == (u8)NL80211_DRV_LINK_ID_NA) {
        mld_link_id = -1;
    }

    wl_mlo_config = nvram_get("wl_mlo_config"); /* Format of nvram wl_mlo_config="-1 -1 -1 -1" */
    if (wl_mlo_config != NULL) {
        int ret;

        ret = sscanf(wl_mlo_config, "%d %d %d %d", &mlo_config[0], &mlo_config[1], &mlo_config[2],
            &mlo_config[3]);

        if ((sizeof(mlo_config) / sizeof(*mlo_config)) == ret &&
            mlo_config[radio_index] < (int)(sizeof(mlo_config) / sizeof(*mlo_config)) &&
            mlo_config[radio_index] >= -1) {
            if (mlo_config[radio_index] == mld_link_id) {
                return; /* No changes are needed */
            }
        }
    }

    mlo_config[radio_index] = mld_link_id;
    memset(new_nvram_val, 0, sizeof(new_nvram_val));
    snprintf(new_nvram_val, sizeof(new_nvram_val), "%d %d %d %d", mlo_config[0], mlo_config[1],
        mlo_config[2], mlo_config[3]);
    set_string_nvram_param("wl_mlo_config", new_nvram_val);
    *nvram_changed |=1;
    wifi_hal_info_print("%s:%d Updating nvram wl_mlo_config with new value: %s\n", __func__,
        __LINE__, new_nvram_val);
}

static struct hostapd_mld *get_mlo_mld(unsigned char mld_unit, char *mac)
{
    if (mld_unit >= MLD_UNIT_COUNT) {
        wifi_hal_error_print("%s:%d: mld_unit:%d out of range (MLD_UNIT_COUNT: %d)!\n", __func__,
            __LINE__, mld_unit, MLD_UNIT_COUNT);
        return NULL;
    }

    if (g_mlo_mld[mld_unit].name[0] == '\0') {
        /* Not initialized yet - Initializing it during the first usage */
        dl_list_init(&g_mlo_mld[mld_unit].links);
        snprintf(g_mlo_mld[mld_unit].name, sizeof(g_mlo_mld[mld_unit].name), "mld_unit_%u",
            mld_unit);
    }
    memcpy(g_mlo_mld[mld_unit].mld_addr, mac, ETH_ALEN);
    return &g_mlo_mld[mld_unit];
}

static struct hostapd_mld *get_slo_mld(wifi_vap_index_t vap_index, char *mac)
{
    if (vap_index >= MAX_VAP) {
        wifi_hal_error_print("%s:%d: vap_index:%d out of range (max vap_index: %d)!\n", __func__,
            __LINE__, vap_index, MAX_VAP - 1);
        return NULL;
    }

    if (g_slo_mld[vap_index].name[0] == '\0') {
        /* Not initialized yet - Initializing it during the first usage */
        dl_list_init(&g_slo_mld[vap_index].links);
        snprintf(g_slo_mld[vap_index].name, sizeof(g_slo_mld[vap_index].name), "slo_mld_id_%u",
            vap_index);
    }
    memcpy(g_slo_mld[vap_index].mld_addr, mac, ETH_ALEN);
    return &g_slo_mld[vap_index];
}

/**
 * @brief Add MLO link and reorganize links to be main link (link_id 0) first_bss
 *
 * @param hapd - pointer to hostapd per-BSS data structure
 * @return int - RETURN_OK upon successful, RETURN_ERR upon error
 */
static void mlo_add_link(struct hostapd_data *hapd)
{
    unsigned char is_first_bss;

    if (hapd->mld_link_id == 0 && hapd->mld->num_links > 0) {
        struct hostapd_data *old_first;

        old_first = hostapd_mld_get_first_bss(hapd);
        deinit_bss(old_first);
    }

    hostapd_mld_add_link(hapd);

    is_first_bss = hostapd_mld_is_first_bss(hapd);
    wifi_hal_info_print("%s:%d: Adding mld link: %s link_id:%d, is_first_bss %d\n",
        __func__, __LINE__, hapd->mld->name, hapd->mld_link_id, is_first_bss);
    if (hapd->mld_link_id == 0 && !is_first_bss) {
        int i;
        int cache_size = 0;
        struct hostapd_data *hapd_cache[MAX_NUM_RADIOS] = { 0 };

        wifi_hal_info_print("%s:%d: hapd->mld_link_id(0) is not first, Going to reorganize links\n",
            __func__, __LINE__);

        for (i = 0; i < MAX_NUM_RADIOS; i++) {
            /* loop until current hapd will be first bss */
            if (!hostapd_mld_is_first_bss(hapd)) {
                hapd_cache[i] = hostapd_mld_get_first_bss(hapd);
                hostapd_mld_remove_link(hapd_cache[i]);
                cache_size++;
                wifi_hal_dbg_print("Removed link mld_link_id %d - i: %d\n",
                    hapd_cache[i]->mld_link_id, i);
            } else {
                break;
            }
        }
        if (cache_size > 0) {
            for (int i = 0; i < cache_size; i++) {
                hostapd_mld_add_link(hapd_cache[i]);
                wifi_hal_dbg_print("Link added back: mld_link_id %d idx i:%d \n",
                    hapd_cache[i]->mld_link_id, i);
            }
        }
    }
}

static void mlo_remove_link(struct hostapd_data *hapd)
{
    wifi_hal_info_print("%s:%d - iface:%s removing VAP from MLD group - mld links num: %d\n",
        __func__, __LINE__, hapd->conf->iface, hapd->mld->num_links);
    if (hapd->mld && hapd->mld->num_links > 1) {
        if (hostapd_mld_is_first_bss(hapd)) {
            /* Leave the shared recources for rest of the links staying in the MLO group */
            hostapd_mld_remove_link(hapd);
            hostapd_mld_add_link(hapd);
        }
    }
    /* We need to detatch/release shared rources before changing mld configuration of BSS.
     * For non first bss are shared resources just set to NULL for first BSS free + set NULL*/
    deinit_bss(hapd);

    hostapd_bss_link_deinit(hapd);
}

int update_hostap_mlo(wifi_interface_info_t *interface)
{
    struct hostapd_bss_config *conf;
    struct hostapd_data *hapd;
    wifi_vap_info_t *vap;
    struct hostapd_mld *new_mld = NULL;
    wifi_mld_common_info_t *mld_conf;
    u8 mld_ap;
    u8 old_mld_link_id;
    int nvram_changed = 0;

    conf = &interface->u.ap.conf;
    hapd = &interface->u.ap.hapd;
    vap = &interface->vap_info;

    set_mld_unit(conf, -1);
    conf->okc = 0;

#ifndef CONFIG_NO_MLD_ONLY_PRIVATE
    if (!is_wifi_hal_vap_private(vap->vap_index)) {
        hapd->mld_link_id = -1;
        return RETURN_OK;
    }
#endif
    mld_conf = &vap->u.bss_info.mld_info.common_info;
    nvram_update_wl_mlo_apply(conf->iface, mld_conf->mld_apply, &nvram_changed);
    nvram_update_wl_mlo_config(vap->radio_index, !conf->disable_11be ? mld_conf->mld_link_id : -1,
        &nvram_changed);
    old_mld_link_id = hapd->mld_link_id;
    hapd->mld_link_id = platform_get_link_id_for_radio_index(vap->radio_index, vap->vap_index);
    mld_ap = (!conf->disable_11be && (hapd->mld_link_id < MAX_NUM_MLD_LINKS));
    nvram_update_wl_bss_mlo_mode(conf->iface, mld_ap ? mld_conf->mld_enable : 0, &nvram_changed);
    if (nvram_changed) {
        wifi_hal_info_print("%s:%d nvram was changed => nvram_commit()\n", __func__, __LINE__);
        nvram_commit();
    }

    if (mld_ap) {
        unsigned char is_mlo_ap;

        conf->mld_ap = mld_ap;
        is_mlo_ap = platform_iface_is_mlo_ap(conf->iface);
        if (is_mlo_ap) {
            set_mld_unit(conf, mld_conf->mld_id);
            new_mld = get_mlo_mld(get_mld_unit(conf), mld_conf->mld_addr);
            /*
             * NOTE: For MLO, we need to enable okc=1, or disable_pmksa_caching=1, otherwise there
             * will be problems with PMKID for link AP
             */
            conf->okc = 1;
        } else {
            new_mld = get_slo_mld(vap->vap_index, hapd->own_addr);
        }
        if (hapd->mld != new_mld || old_mld_link_id != hapd->mld_link_id) {
            if (hapd->mld)
                mlo_remove_link(hapd);
            hapd->mld = new_mld;
            mlo_add_link(hapd);
        }

        wifi_hal_dbg_print("%s:%d: Setup of first (%d) link (%u) BSS of %s %s for VAP %s\n",
            __func__, __LINE__, hostapd_mld_is_first_bss(hapd), hapd->mld_link_id,
            (is_mlo_ap ? "MLO" : "SLO"), hapd->mld->name, vap->vap_name);
    } else {
        if (hapd->mld) {
            mlo_remove_link(hapd);
            hapd->mld = NULL;
        }
        conf->mld_ap = mld_ap;
    }

    wifi_hal_info_print("%s:%d: iface:%s - mld_ap:%d mld_unit:%u mld_link_id:%u\n", __func__,
        __LINE__, conf->iface, conf->mld_ap, get_mld_unit(conf), hapd->mld_link_id);

    return RETURN_OK;
}
#endif /* CONFIG_IEEE80211BE */
