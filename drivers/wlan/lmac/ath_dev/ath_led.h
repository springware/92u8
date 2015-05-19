/*
 * Copyright (c) 2009, Atheros Communications Inc.
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

/*
 * Public Interface for LED control module
 */

/*
 * Definitions for the Atheros LED control module.
 */
#ifndef _DEV_ATH_LED_H
#define _DEV_ATH_LED_H

#include "ath_timer.h"

#if ATH_SUPPORT_LED

/**
 * Added for customizing LED control operations
 */
#define IS_LED_ENABLE(_ledFunc)     ((_ledFunc) & 0x1)          /* Is led mode enabled */
#define LED_PIN(_ledFunc)           (((_ledFunc) & 0xe) >> 1)   /* Led Gpio Pin        */
#define LED_POLARITY(_ledFunc)      (((_ledFunc) & 0x10) >> 4)  /* Led Polarity 1-Asserted High */

#ifdef ATH_USB
#define	ATH_LED_LOCK_INIT(_lc)                OS_USB_LOCK_INIT(&(_lc)->ledLock)
#define	ATH_LED_LOCK_DESTROY(_lc)             OS_USB_LOCK_DESTROY(&(_lc)->ledLock)
#define	ATH_LED_LOCK(_lc)                     OS_USB_LOCK(&(_lc)->ledLock)
#define	ATH_LED_UNLOCK(_lc)                   OS_USB_UNLOCK(&(_lc)->ledLock)
#else
#define	ATH_LED_LOCK_INIT(_LedControl)        spin_lock_init(&(_LedControl)->ledLock)
#define	ATH_LED_LOCK_DESTROY(_LedControl)
#ifdef ATH_SUPPORT_LINUX_STA
#define	ATH_LED_LOCK(_LedControl)             spin_lock_dpc(&(_LedControl)->ledLock)
#define	ATH_LED_UNLOCK(_LedControl)           spin_unlock_dpc(&(_LedControl)->ledLock)
#else
#define	ATH_LED_LOCK(_LedControl)             spin_lock(&(_LedControl)->ledLock)
#define	ATH_LED_UNLOCK(_LedControl)           spin_unlock(&(_LedControl)->ledLock)
#endif
#endif /* ATH_USB */

typedef enum _led_states {
    LED_OFF = 0,          // 0
    LED_ON  = 1,          // 1

    NUMBER_LED_STATES     // 2
} LED_STATE;

typedef struct gpioFuncInfo {
    u_int8_t    enabled;                     // function is enabled
    u_int8_t    pin;                         // pin used by this function
    u_int8_t    shared;                      // pin is shared
    u_int8_t    value[NUMBER_LED_STATES];    // values used to set the LED to possible states
} GPIO_FUNC_INFO;

typedef struct {
    u_int32_t    rate;        // rate in Mbs
    u_int32_t    timeOn;      // LED ON time in ms
    u_int32_t    timeOff;     // LED OFF time in ms
} LED_BLINK_RATES;

struct ath_led_control;

typedef void (*LED_CONTROL_FUNCTION) (struct ath_led_control *pLedControl, LED_STATE state);

typedef struct blinking_control {
    LED_STATE               ledState;                          // current LED state
    LED_CONTROL_FUNCTION    ledControlFunction;                // function used to make LED blink, determining which LED blinks
} BLINKING_CONTROL, *PBLINKING_CONTROL;

struct led_state_info
{
    LED_STATE    link_led_state;
    LED_STATE    activity_led_state;
    LED_STATE    connection_led_state;
    u_int32_t    blinking_cadence[NUMBER_LED_STATES];
};

#define NUMBER_HAL_LED_STATES  (HAL_LED_RUN + 1)

typedef struct ath_led_control {
    osdev_t                osdev;                             // pointer to OS device
    struct ath_softc       *sc;                               // pointer to sc
    struct ath_hal         *ah;                               // pointer to HAL object

    // Table containing LED states and ON/OFF times for each HAL state.
    // This table will be initialized by ath_initialize_led_cadence_table.
    struct led_state_info  led_info[NUMBER_HAL_LED_STATES];

    const LED_BLINK_RATES  *blinkRateTable;                   // blinking rate table to be used
    int8_t                 blinkRateTableLength;              // number of entries in the blinking rate table
    struct ath_timer       ledHeartbeatTimer;                 // used for periodic LED operations
    struct ath_timer       ledFastTimer;                      // timer used for high-frequency traffic-related blinking
#ifdef ATH_USB
    usblock_t              ledLock;
#else
    spinlock_t             ledLock;                           // Need to synchronize access to hardware between the 2 timers
#endif

    u_int32_t              stateDuration[NUMBER_LED_STATES];  // duration for each of the LED states
    BLINKING_CONTROL       blinkingControlNotConnected;       // LED state/which LED to blink when not connected
    BLINKING_CONTROL       blinkingControlConnected;          // LED state/which LED to blink when connected
    HAL_LED_STATE          halState;                          // current HAL state
    HAL_LED_STATE          saveState;                         // HAL state when scan started
    atomic_t               dataBytes;                         // number of rx/tx data bytes in a certain period
    systime_t              scanStartTimestamp;                // start of external scan
    systime_t              ledStateTimeStamp;                 // start of current LED state
    systime_t              trafficStatisticsTimeStamp;
    u_int32_t              scanStateDuration;                 // fixed amount of time the scan blinking pattern must be shown

    // flags
    u_int32_t              cardBusLEDControl     : 1,         // LEDs controlled by cardbus
                           ledControlDisabled    : 1,         // Indicates NIC is powered off (Radio Off, Sleeping, etc.)
                           ledSuspended          : 1,         // Indicates system entered suspended state (S3)
                           softLEDEnable         : 1,         // Enable software LED control to work in WIFI LED mode
                           customLedControl      : 1,         // GPIO pins used
                           enhancedLedControl    : 1,         // Registry entries linkLEDFunc, activityLEDFunc or connectionLEDFunc present
                           swFastBlinkingControl : 1;         // Fast blinking during connected state controlled by sw

    GPIO_FUNC_INFO         gpioFunc[NUM_GPIO_FUNCS];          // Control struct for each GPIO pin
    int8_t                 sharedGpioFunc[NUM_GPIO_FUNCS];    // Indicate GPIO pin is shared

    int8_t                 gpioLedCustom;                     // Defines customer-specific blinking requirements
    int8_t                 DisableLED01;                      // LED_0 or LED_1 in PCICFG register is used for other purposes
    u_int8_t               sharedGpioFunc0;                   // gpioFunc0 (link LED) is shared with other devices.
    u_int32_t              numGpioPins;                       // Number of GPIO pins supported by the hardware. (Must be 32bits.)

} ATH_LED_CONTROL;


#define ATH_LED_CONTROL_OBJ(xxx)   struct ath_led_control xxx

// Function exported by the LED module
void ath_led_reinit(struct ath_softc *sc);
void ath_led_initialize_control (struct ath_softc       *sc, 
                                 osdev_t                sc_osdev,
                                 struct ath_hal         *ah,
                                 struct ath_led_control *pLedControl,
                                 struct ath_reg_parm    *pRegParam,
                                 HAL_BOOL               bAllowCardBusLedControl);
void ath_led_free_control       (struct ath_led_control *pLedControl);
void ath_led_set_state          (struct ath_led_control *pLedControl, HAL_LED_STATE newHalState);
void ath_led_start_control      (struct ath_led_control *pLedControl, int radioOn);
void ath_led_halt_control       (struct ath_led_control *pLedControl);
void ath_led_scan_start         (struct ath_led_control *pLedControl);
void ath_led_scan_end           (struct ath_led_control *pLedControl);
void ath_led_enable             (struct ath_led_control *pLedControl);
void ath_led_disable            (struct ath_led_control *pLedControl);
void ath_led_report_data_flow   (struct ath_led_control *pLedControl, int32_t byteCount);
void ath_led_suspend            (ath_dev_t dev);

#else /* ATH_SUPPORT_LED */

#define ATH_LED_CONTROL_OBJ(xxx)   u_int8_t xxx 

#define ath_led_set_state(pLedControl,newHalState)            /* */
#define ath_led_start_control(pLedControl,radioOn)            /* */
#define ath_led_halt_control(pLedControl)                     /* */
#define ath_led_scan_start(pLedControl)                       /* */
#define ath_led_scan_end(pLedControl)                         /* */ 
#define ath_led_enable(pLedControl)                           /* */
#define ath_led_disable(pLedControl)                          /* */
#define ath_led_report_data_flow(pLedControl,byteCount)       /* */
#define ath_led_suspend(dev)                                  /* */
#define ath_led_reinit(sc)                                    /* */
#define ath_led_initialize_control(sc,osdev,ah,control,reg, bAllow)   /* */
#define ath_led_free_control(ontrol)

#endif /* ATH_SUPPORT_LED */

#endif /* _DEV_ATH_LED_H */