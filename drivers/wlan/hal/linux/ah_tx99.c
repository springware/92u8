/*
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2002-2005 Atheros Communications, Inc.
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef __i386__
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif
#else
#include <linux/config.h>
#endif
#endif
#include "opt_ah.h"

/*
** Linux Includes
*/
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/delay.h>

/*
** HTC Includes
*/
//#include "../../htc/inc/wmi.h"
#include "../../htc/inc/wmi_cmd.h"
//#include "../../htc/inc/wmi_host_api.h" 

/*
** HAL Includes
*/
#include "ah.h"
#include "ah_internal.h"
#include "ah_devid.h"
#include "ah_eeprom.h"
#include "ar5416/ar5416reg.h"
#include "ar5416/ar5416phy.h"
#include "ar5416/ar5416eep.h"

extern a_status_t __ahdecl 
wmi_cmd(void *wmi_handle, WMI_COMMAND_ID cmdId, u_int8_t *pCmdBuffer, u_int32_t length, u_int8_t *pRspBuffer, u_int32_t rspLen, u_int32_t timeout);

struct ath_tx99_tgt {
	u_int32_t	txrate;		/* tx rate */
	u_int32_t	txpower;	/* tx power */
	u_int32_t	txchain;	/* tx chainmask */
	u_int32_t	htmode;		/* channel width mode, e.g. HT20, HT40 */
	u_int32_t	type;		/* single carrier or frame type */
	u_int32_t	chtype;		/* channel type */
	u_int32_t	txantenna;	/* tx antenna */
};

void 
ah_tx99_tx_stopdma(struct ath_hal *ah, u_int32_t hwq_num)
{
	u_int8_t cmd_status;

	if(wmi_cmd(ah->hal_wmi_handle,
		WMI_STOP_TX_DMA_CMDID,
		(u_int8_t *)&hwq_num,
		sizeof(u_int32_t),
		(u_int8_t *)&cmd_status,
		sizeof(cmd_status),
		100))
	{
		ath_hal_printf(NULL, "stop dma fail stat = %x\n", cmd_status);
	}
}

void 
ah_tx99_drain_alltxq(struct ath_hal *ah)
{
    u_int8_t cmd_status;
    
    /* drain all target wireless tx queues */
	if(wmi_cmd(ah->hal_wmi_handle,
                WMI_DRAIN_TXQ_ALL_CMDID,
                NULL,
                0,
                &cmd_status,
                sizeof(cmd_status),
                100))
	{
		ath_hal_printf(NULL, "drain tx queue fail stat = %x\n", cmd_status);
	}
}

void 
ah_tx99_channel_pwr_update(struct ath_hal *ah, HAL_CHANNEL *c, u_int32_t txpower)
{
#define PWR_MAS(_r, _s)     (((_r) & 0x3f) << (_s))

    int16_t pwr_offset = 0;
    static int16_t ratesArray[Ar5416RateSize] = { 0 };
    int32_t i;
    int32_t cck_ofdm_delta = 0;
    u_int8_t ht40PowerIncForPdadc = 2;
    
    pwr_offset = ah->ah_pwr_offset;

    for (i = 0; i < Ar5416RateSize; i++)
        ratesArray[i] = txpower - pwr_offset*2;

    /* Write the OFDM power per rate set */
    OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE1,
        PWR_MAS(ratesArray[rate18mb], 24)
          | PWR_MAS(ratesArray[rate12mb], 16)
          | PWR_MAS(ratesArray[rate9mb],  8)
          | PWR_MAS(ratesArray[rate6mb],  0)
    );

    OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE2,
        PWR_MAS(ratesArray[rate54mb], 24)
          | PWR_MAS(ratesArray[rate48mb], 16)
          | PWR_MAS(ratesArray[rate36mb],  8)
          | PWR_MAS(ratesArray[rate24mb],  0)
    );

    if ( IS_CHAN_2GHZ(c) ) 
    {
        /* Write the CCK power per rate set */
        OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE3,
            PWR_MAS(ratesArray[rate2s]-cck_ofdm_delta, 24)
              | PWR_MAS(ratesArray[rate2l]-cck_ofdm_delta,  16)
              | PWR_MAS(ratesArray[rateXr],  8) /* XR target power */
              | PWR_MAS(ratesArray[rate1l]-cck_ofdm_delta,   0)
        );

        OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE4,
            PWR_MAS(ratesArray[rate11s]-cck_ofdm_delta, 24)
              | PWR_MAS(ratesArray[rate11l]-cck_ofdm_delta, 16)
              | PWR_MAS(ratesArray[rate5_5s]-cck_ofdm_delta,  8)
              | PWR_MAS(ratesArray[rate5_5l]-cck_ofdm_delta,  0)
        );
    }

    /* Write the HT20 power per rate set */
    OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE5,
        PWR_MAS(ratesArray[rateHt20_3], 24)
          | PWR_MAS(ratesArray[rateHt20_2],  16)
          | PWR_MAS(ratesArray[rateHt20_1],  8)
          | PWR_MAS(ratesArray[rateHt20_0],   0)
    );

    OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE6,
        PWR_MAS(ratesArray[rateHt20_7], 24)
          | PWR_MAS(ratesArray[rateHt20_6],  16)
          | PWR_MAS(ratesArray[rateHt20_5],  8)
          | PWR_MAS(ratesArray[rateHt20_4],   0)
    );

    if ( IS_CHAN_HT(c) ) 
    {
        /* Write the HT40 power per rate set */
        /* Correct the difference between HT40 and HT20/Legacy */
        OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE7,
            PWR_MAS(ratesArray[rateHt40_3] + ht40PowerIncForPdadc, 24)
              | PWR_MAS(ratesArray[rateHt40_2] + ht40PowerIncForPdadc,  16)
              | PWR_MAS(ratesArray[rateHt40_1] + ht40PowerIncForPdadc,  8)
              | PWR_MAS(ratesArray[rateHt40_0] + ht40PowerIncForPdadc,   0)
        );

        OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE8,
            PWR_MAS(ratesArray[rateHt40_7] + ht40PowerIncForPdadc, 24)
              | PWR_MAS(ratesArray[rateHt40_6] + ht40PowerIncForPdadc,  16)
              | PWR_MAS(ratesArray[rateHt40_5] + ht40PowerIncForPdadc,  8)
              | PWR_MAS(ratesArray[rateHt40_4] + ht40PowerIncForPdadc,   0)
        );

        /* Write the Dup/Ext 40 power per rate set */
        OS_REG_WRITE(ah, AR_PHY_POWER_TX_RATE9,
            PWR_MAS(ratesArray[rateExtOfdm], 24)
              | PWR_MAS(ratesArray[rateExtCck]-cck_ofdm_delta,  16)
              | PWR_MAS(ratesArray[rateDupOfdm],  8)
              | PWR_MAS(ratesArray[rateDupCck]-cck_ofdm_delta,   0)
        );
    }
#undef PWR_MAS
}

void 
ah_tx99_start(struct ath_hal *ah, u_int8_t *data)
{
    u_int8_t cmd_status;
    static struct ath_tx99_tgt tx99_tgt;

    memcpy(&tx99_tgt, data, sizeof(struct ath_tx99_tgt));
    //ath_hal_printf(NULL, "rate=%d, power=%d, chain=%d, htmode=%d, type=%d, chtype=%d, antenna=%d \n", 
    //      tx99_tgt.txrate, tx99_tgt.txpower, tx99_tgt.txchain, tx99_tgt.htmode, tx99_tgt.type, tx99_tgt.chtype, tx99_tgt.txantenna);

    if(wmi_cmd(ah->hal_wmi_handle,
				WMI_TX99_START_CMDID,
				(u_int8_t *)&tx99_tgt,
				sizeof(struct ath_tx99_tgt),
				(u_int8_t *)&cmd_status,
				sizeof(cmd_status),
				100))
	{
		ath_hal_printf(NULL, "set tx99 enable fail stat = %x\n", cmd_status);
	}
}

void 
ah_tx99_stop(struct ath_hal *ah)
{	
    u_int8_t cmd_status;
    
    OS_REG_WRITE(ah, AR_PHY_TEST, OS_REG_READ(ah, AR_PHY_TEST) &~ PHY_AGC_CLR);
	OS_REG_WRITE(ah, AR_DIAG_SW, OS_REG_READ(ah, AR_DIAG_SW) &~ (AR_DIAG_FORCE_RX_CLEAR | AR_DIAG_IGNORE_VIRT_CS));

	/* tx stop */
	if(wmi_cmd(ah->hal_wmi_handle,
            WMI_TX99_STOP_CMDID,
            NULL,
			0,
			(u_int8_t *)&cmd_status,
			sizeof(cmd_status),
			100))
	{
		ath_hal_printf(NULL, "set tx99 stop fail stat = %x\n", cmd_status);
	}
}
