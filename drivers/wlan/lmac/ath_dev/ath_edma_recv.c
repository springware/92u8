/*
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
 *
 *  Implementation of receive path in atheros OS-independent layer.
 */

#include "ath_internal.h"
#include "ath_edma.h"

#ifndef REMOVE_PKT_LOG
#include "pktlog.h"
extern struct ath_pktlog_funcs *g_pktlog_funcs;
#endif

#ifdef ATH_SUPPORT_DFS
#include "dfs.h"
#endif

#if ATH_SUPPORT_SPECTRAL
#include "spectral.h"
#endif

#if ATH_SUPPORT_EDMA
#define ATH_RX_DESC_WAR


void
ath_edma_attach(struct ath_softc *sc, struct ath_ops **ops)
{
    /*
     * Check if the chip supports enhanced DMA support.
     */
    if (ath_hal_hasenhanceddmasupport(sc->sc_ah)) {
        sc->sc_enhanceddmasupport = 1;
        (*ops)->rx_init = ath_rx_edma_init;
        (*ops)->rx_proc = ath_rx_edma_tasklet;
        (*ops)->rx_requeue = ath_rx_edma_requeue;
        (*ops)->rx_cleanup = ath_rx_edma_cleanup;
        (*ops)->tx_proc = ath_tx_edma_tasklet;
    } else {
        sc->sc_enhanceddmasupport = 0;
    }
    /* 
     * Check if the chip supports HW Uapsd trigger 
     */
    if (ath_hal_hashwuapsdtrig(sc->sc_ah)) {
        sc->sc_hwuapsdtrig = 1;
    } else {
        sc->sc_hwuapsdtrig = 0;
    }
    
}

static void
ath_rx_removebuffer(struct ath_softc *sc, HAL_RX_QUEUE qtype)
{
    int i, size;
    struct ath_buf *bf;
    wbuf_t wbuf;
    struct ath_rx_edma *rxedma;

    rxedma = &sc->sc_rxedma[qtype];

    size = rxedma->rxfifohwsize;

    /* Remove all buffers from rx queue and insert in free queue */
    for (i = 0; i < size; i++) {
        wbuf = rxedma->rxfifo[i];
        if (wbuf) {
            bf = ATH_GET_RX_CONTEXT_BUF(wbuf);
            if (!bf) {
                printk("%s[%d] PANIC wbuf %p Index %d\n", __func__, __LINE__, wbuf, i);
            }
            TAILQ_INSERT_TAIL(&sc->sc_rxbuf, bf, bf_list);
            rxedma->rxfifo[i] = NULL;
            rxedma->rxfifodepth--;
        }
    }

    /* reset head and tail indices */
    rxedma->rxfifoheadindex = 0;
    rxedma->rxfifotailindex = 0;
    if (rxedma->rxfifodepth)
        printk("PANIC depth non-zero %d\n", rxedma->rxfifodepth);
}

/*
 * allocate rx fifo list to represent MAC fifo
 */
static int
ath_rxfifo_alloc(struct ath_softc *sc, HAL_RX_QUEUE qtype)
{
    struct ath_rx_edma *rxedma;
    int bsize, error;

    rxedma = &sc->sc_rxedma[qtype];

    error = ath_hal_getrxfifodepth(sc->sc_ah, qtype, &rxedma->rxfifohwsize);
    if (error)
        return error;

    bsize = sizeof(wbuf_t) * rxedma->rxfifohwsize;

    rxedma->rxfifo = (wbuf_t *)OS_MALLOC(sc->sc_osdev, bsize, GFP_KERNEL);
    if (rxedma->rxfifo == NULL)
        return -ENOMEM;

    rxedma->rxfifoheadindex = 0;
    rxedma->rxfifotailindex = 0;
    rxedma->rxfifodepth = 0;

    OS_MEMZERO(rxedma->rxfifo, bsize);
    TAILQ_INIT(&rxedma->rxqueue);
    ATH_RXQ_LOCK_INIT(rxedma);

    return 0;
}

int
ath_rx_edma_init(ath_dev_t dev, int nbufs)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(dev);
    wbuf_t wbuf;
    struct ath_rx_status *rxs;
    struct ath_buf *bf;
    int error = 0;
    int i, bsize;

    do {
        ATH_RXFLUSH_LOCK_INIT(sc);
        sc->sc_rxflush = 0;
        ATH_RXBUF_LOCK_INIT(sc);

        /*
         * Cisco's VPN software requires that drivers be able to
         * receive encapsulated frames that are larger than the MTU.
         * Since we can't be sure how large a frame we'll get, setup
         * to handle the larges on possible.
         *
         * XXX Add 64 bytes for Rx Status
         */
        // Get the receive buffer size. The OS layer can use the rxstatus len to 
        // figure out how much to allocate. 
        sc->sc_rxbufsize = OS_MAX_RXBUF_SIZE(sc->sc_rxstatuslen);

        DPRINTF(sc,ATH_DEBUG_RESET, "%s: cachelsz %u rxbufsize %u\n",
                __func__, sc->sc_cachelsz, sc->sc_rxbufsize);

        /*
         * Sets receive buffer size in the hardware.
         */
        ath_hal_setrxbufsize(sc->sc_ah, sc->sc_rxbufsize - sc->sc_rxstatuslen);

        /*
         * allocate rx fifo list to represent high priority MAC fifo
         */
        error = ath_rxfifo_alloc(sc, HAL_RX_QUEUE_HP);
        if (error)
            goto fail;
            
        /*
         * allocate rx fifo list to represent low priority MAC fifo
         */
        error = ath_rxfifo_alloc(sc, HAL_RX_QUEUE_LP);
        if (error)
            goto fail;
            

        /* allocate ath_buf pool */
        bsize = sizeof(struct ath_buf) * nbufs;
        bf = (struct ath_buf *)OS_MALLOC(sc->sc_osdev, bsize, GFP_KERNEL);
        if (bf == NULL) {
            error = -ENOMEM;
            goto fail;
        }

        OS_MEMZERO(bf, bsize);
        TAILQ_INIT(&sc->sc_rxbuf);
        sc->sc_rxbufptr = bf;

        /* allocate ath_rx_status pool */
        bsize = sizeof(struct ath_rx_status) * nbufs;
        rxs = (struct ath_rx_status *)OS_MALLOC(sc->sc_osdev, bsize, GFP_KERNEL);
        if (rxs == NULL) {
            error = -ENOMEM;
            goto fail;
        }
        OS_MEMZERO(rxs, bsize);
        sc->sc_rxsptr = rxs;

        for (i = 0; i < nbufs; i++, bf++, rxs++) {
            wbuf = ath_rxbuf_alloc(sc, sc->sc_rxbufsize);
            if (wbuf == NULL) {
                error = -ENOMEM;
                break;
            }

            bf->bf_mpdu = wbuf;
            bf->bf_buf_addr[0] = wbuf_map_single(sc->sc_osdev, wbuf, BUS_DMA_FROMDEVICE,
                                              OS_GET_DMA_MEM_CONTEXT(bf, bf_dmacontext));
            ATH_SET_RX_CONTEXT_BUF(wbuf, bf);
            bf->bf_desc = (void *)rxs;

            TAILQ_INSERT_TAIL(&sc->sc_rxbuf, bf, bf_list);
        }

        if (!error)
            sc->sc_num_rxbuf = nbufs;
        else
            sc->sc_num_rxbuf = i;
    } while (0);

fail:
    if (error) {
        ath_rx_edma_cleanup(sc);
    }

    return error;
}

/*
 * Reclaim all rx queue resources
 */
void
ath_rx_edma_cleanup(ath_dev_t dev)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(dev);
    wbuf_t wbuf;
    struct ath_buf *bf;
    u_int32_t nbuf = 0;

    /*
     * Remove buffers from FIFOs and put them back to free list.
     * Free FIFO memory.
     */
    if (sc->sc_rxedma[HAL_RX_QUEUE_HP].rxfifo) {
        ath_rx_removebuffer(sc, HAL_RX_QUEUE_HP);
        OS_FREE(sc->sc_rxedma[HAL_RX_QUEUE_HP].rxfifo);
        sc->sc_rxedma[HAL_RX_QUEUE_HP].rxfifo = NULL;
    }
    if (!TAILQ_EMPTY(&sc->sc_rxedma[HAL_RX_QUEUE_HP].rxqueue)) {
        TAILQ_CONCAT(&sc->sc_rxbuf, &sc->sc_rxedma[HAL_RX_QUEUE_HP].rxqueue, bf_list);
        TAILQ_INIT(&sc->sc_rxedma[HAL_RX_QUEUE_HP].rxqueue);
    }

    if (sc->sc_rxedma[HAL_RX_QUEUE_LP].rxfifo) {
        ath_rx_removebuffer(sc, HAL_RX_QUEUE_LP);
        OS_FREE(sc->sc_rxedma[HAL_RX_QUEUE_LP].rxfifo);
        sc->sc_rxedma[HAL_RX_QUEUE_LP].rxfifo = NULL;
    }
    if (!TAILQ_EMPTY(&sc->sc_rxedma[HAL_RX_QUEUE_LP].rxqueue)) {
        TAILQ_CONCAT(&sc->sc_rxbuf, &sc->sc_rxedma[HAL_RX_QUEUE_LP].rxqueue, bf_list);
        TAILQ_INIT(&sc->sc_rxedma[HAL_RX_QUEUE_LP].rxqueue);
    }

    /*
     * Free all wbufs in the free list.
     */
    TAILQ_FOREACH(bf, &sc->sc_rxbuf, bf_list) {
        wbuf = bf->bf_mpdu;
        if (wbuf) {
            nbuf++;
            wbuf_release(sc->sc_osdev, wbuf);
        }
    }

    ASSERT(sc->sc_num_rxbuf == nbuf);

    TAILQ_INIT(&sc->sc_rxbuf);

    /* Free ath_rx_status pool */
    if (sc->sc_rxsptr) {
        OS_FREE(sc->sc_rxsptr);
        sc->sc_rxsptr = NULL;
    }

    /* Free ath_buf pool */
    if (sc->sc_rxbufptr) {
        OS_FREE(sc->sc_rxbufptr);
        sc->sc_rxbufptr = NULL;
    }

    ATH_RXBUF_LOCK_DESTROY(sc);
    //ATH_RXFLUSH_LOCK_DESTROY(sc);
}

/*
 * Add a wbuf from the free list to the rx fifo.
 * Context: Interrupt
 * NOTE: Caller should hold the rxbuf lock.
 */
static void
ath_rx_buf_link(struct ath_softc *sc, struct ath_buf *bf, HAL_RX_QUEUE qtype)
{
    struct ath_hal *ah = sc->sc_ah;
    struct ath_rx_edma *rxedma;

    rxedma = &sc->sc_rxedma[qtype];

//    ATH_RXBUF_RESET(bf);
#ifdef ATH_RX_DESC_WAR
	bf->bf_status = 0;
#endif
    /* Reset the status part */
    OS_MEMZERO(wbuf_raw_data(bf->bf_mpdu), sc->sc_rxstatuslen);

	/*
	** Since the descriptor header (48 bytes, which is 64 bytes, 2-3 cache lines
	** depending on alignment) is cached, we need to sync to ensure harware sees
	** the proper information, and we don't get inconsistent cache data.  So sync
	*/

     OS_SYNC_SINGLE(sc->sc_osdev, bf->bf_buf_addr[0], sc->sc_rxstatuslen,
                    BUS_DMA_TODEVICE, OS_GET_DMA_MEM_CONTEXT(bf, bf_dmacontext));

    rxedma->rxfifo[rxedma->rxfifotailindex] = bf->bf_mpdu;

    /* advance the tail pointer */
    INCR(rxedma->rxfifotailindex, rxedma->rxfifohwsize);

    rxedma->rxfifodepth++;

    if (rxedma->rxfifodepth > rxedma->rxfifohwsize)
        printk("PANIC depth more than size %d sz %d\n",
                rxedma->rxfifodepth, rxedma->rxfifohwsize);

    /* push this buffer in the MAC Rx fifo */
    ath_hal_putrxbuf(ah, bf->bf_buf_addr[0], qtype);

}

static void
ath_rx_addbuffer(struct ath_softc *sc, HAL_RX_QUEUE qtype, int size)
{
    int i;
    struct ath_buf *bf, *tbf;
    struct ath_rx_edma *rxedma;

    rxedma = &sc->sc_rxedma[qtype];

    if (rxedma->rxfifodepth == rxedma->rxfifohwsize) {
        ath_rx_removebuffer(sc, qtype);
    }

    if (TAILQ_EMPTY(&sc->sc_rxbuf)) {
		DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s[%d]: Out of buffers\n", __func__, __LINE__);
		return;
	}

    /* Add free buffers to rx queue */
    i = 0;
    TAILQ_FOREACH_SAFE(bf, &sc->sc_rxbuf, bf_list, tbf) {
        if (i == size)
            break;

        if (rxedma->rxfifodepth >= rxedma->rxfifohwsize) {
            printk("%s: size = %d rxfifodepth=%d\n", __func__, size, rxedma->rxfifodepth);
            break;
        }

        TAILQ_REMOVE(&sc->sc_rxbuf, bf, bf_list);
        if (bf == NULL) {
			DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s[%d]: Out of buffers\n", __func__, __LINE__);
            break;
        }
        i++;
        ath_rx_buf_link(sc, bf, qtype);
    }
}

static void
ath_rx_addbuffer_intsafe(struct ath_softc *sc)
{
    ath_rx_addbuffer(sc, HAL_RX_QUEUE_HP, sc->sc_rxedma[HAL_RX_QUEUE_HP].rxfifohwsize);
    ath_rx_addbuffer(sc, HAL_RX_QUEUE_LP, sc->sc_rxedma[HAL_RX_QUEUE_LP].rxfifohwsize);
}


void 
ath_edmaAllocRxbufsForFreeList(struct ath_softc *sc)
{
    struct ath_buf *bf;
    wbuf_t new_wbuf;
    int count = 0;
    
    while ((bf = sc->sc_rxfreebuf) != NULL) {
        if ((new_wbuf = ATH_ALLOCATE_RXBUFFER(sc, sc->sc_rxbufsize)) != NULL) {
            // Map the ath_buf to the mbuf, load the physical mem map.
            bf->bf_buf_addr[0] = wbuf_map_single(sc->sc_osdev, new_wbuf, BUS_DMA_FROMDEVICE,
                                              OS_GET_DMA_MEM_CONTEXT(bf, bf_dmacontext));
            if (bf->bf_buf_addr[0]) {
                bf->bf_mpdu = new_wbuf;
                // Set the context area to point to the ath_buf.
                ATH_SET_RX_CONTEXT_BUF(new_wbuf, bf);
                // We are always working with the free queue head. Since we allocated a buffer for it, remove it
                sc->sc_rxfreebuf = bf->bf_next;
                bf->bf_next = NULL;
                if (sc->sc_rxfreebuf == NULL) {
                    sc->sc_rxfreetail = NULL;
                }
                //ath_rx_requeue(sc, new_wbuf);
                // Queue the packet into the free queue
                TAILQ_INSERT_TAIL(&sc->sc_rxbuf, bf, bf_list);
                count++;
            }
            else {
                // Some weird problem ?
                DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s[%d]: Could not map mbuf into physical memory. Retrying.\n", __func__, __LINE__);
                // Dont delink bf. Just free the mbuf  and try to allocate.                   
                bf->bf_mpdu = NULL;
                wbuf_free(new_wbuf);
                continue;
            }
        }
        else {
            DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s[%d] --- Could not allocate Mbuf - try again later \n", __func__, __LINE__);
            // Could not alloc Rx bufs. Try again later.
            break;
        }
    }

   
    DPRINTF(sc, ATH_DEBUG_RX_PROC, "---- %s[%d] ---- Fed back %d buffers to HW Q ---\n", __func__, __LINE__, count);
}


/*
 * Enable the receive h/w following a reset.
 */
int
ath_edma_startrecv(struct ath_softc *sc)
{
    struct ath_hal *ah = sc->sc_ah;
    struct ath_buf *bf;

    ATH_RXBUF_LOCK(sc);
    
    // Check the free athbuf list. If there are athbufs here, try to alloc some mbufs for them.
    if (sc->sc_rxfreebuf) {      
        ath_edmaAllocRxbufsForFreeList(sc);
    } 

    bf = TAILQ_FIRST(&sc->sc_rxbuf);
    if (bf == NULL) {
        ATH_RXBUF_UNLOCK(sc);
        return -ENOMEM;
    }
    
#if USE_MULTIPLE_BUFFER_RCV
    if (sc->sc_rxpending) {
        ath_rx_edma_requeue(sc, sc->sc_rxpending);
        sc->sc_rxpending = NULL;
    }              
#endif /* USE_MULTIPLE_BUFFER_RCV */
    ath_hal_rxena(ah);      /* enable recv fifo */

    OS_EXEC_INTSAFE(sc->sc_osdev, ath_rx_addbuffer_intsafe, sc);
    DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s[%d]: RxFifoHeadHP %d RxFifoTailHP %d\n", __func__, __LINE__,
           sc->sc_rxedma[HAL_RX_QUEUE_HP].rxfifoheadindex,
           sc->sc_rxedma[HAL_RX_QUEUE_HP].rxfifotailindex);
    DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s[%d]: RxFifoHeadLP %d RxFifoTailLP %d\n", __func__, __LINE__,
           sc->sc_rxedma[HAL_RX_QUEUE_LP].rxfifoheadindex,
           sc->sc_rxedma[HAL_RX_QUEUE_LP].rxfifotailindex);

    ATH_RXBUF_UNLOCK(sc);

    ath_opmode_init(sc);        /* set filters, etc. */
    ath_hal_startpcurecv(ah, sc->sc_scanning);	/* re-enable PCU/DMA engine */
    return 0;
}

static void
ath_rx_removebuffer_intsafe(struct ath_softc *sc)
{
    if (sc->sc_rxedma[HAL_RX_QUEUE_HP].rxfifo) {
        ath_rx_removebuffer(sc, HAL_RX_QUEUE_HP);
    }
    if (sc->sc_rxedma[HAL_RX_QUEUE_LP].rxfifo) {
        ath_rx_removebuffer(sc, HAL_RX_QUEUE_LP);
    }
}

/*
 * Disable the receive h/w in preparation for a reset.
 */
HAL_BOOL
ath_edma_stoprecv(struct ath_softc *sc, int timeout)
{
    struct ath_hal *ah = sc->sc_ah;
    u_int64_t tsf;
    HAL_BOOL stopped = AH_TRUE;

    if (!sc->sc_removed) {
        if (sc->sc_fastabortenabled) {
            stopped = ath_hal_setrxabort(ah, AH_TRUE); /* abort and disable PCU */
        } else {
            ath_hal_stoppcurecv(ah); /* disable PCU */
        }
        ath_hal_setrxfilter(ah, 0);	/* clear recv filter */
        stopped &= ath_hal_stopdmarecv(ah, timeout);	/* stop and disable Rx DMA */
        tsf = ath_hal_gettsf64(ah);
    }

    ATH_RXBUF_LOCK(sc);
    OS_EXEC_INTSAFE(sc->sc_osdev, ath_rx_removebuffer_intsafe, sc);
    ATH_RXBUF_UNLOCK(sc);

    return stopped;
}

/*
 * Helper routine for ath_rx_edma_requeue
 * Context: ISR
\ */
struct ath_rx_edma_requeue_request {
    struct ath_softc *sc;
    struct ath_buf *bf;
};

static void ath_rx_edma_requeue_intsafe(struct ath_rx_edma_requeue_request *requeue)
{
    struct ath_softc *sc = requeue->sc;
    struct ath_buf *bf = requeue->bf;
    struct ath_hal *ah = sc->sc_ah;

    TAILQ_INSERT_TAIL(&sc->sc_rxbuf, bf, bf_list);

    /* If RXEOL interrupts were disabled (due to no buffers available), re-enable RXEOL interrupts. */
    if (!(sc->sc_imask & HAL_INT_RXEOL)) {
        if (sc->sc_edmarxdpc) {
            /* In rxdpc - so do not enable interrupt, just set the sc_imask
             * interrupt gets enabled at the end of DPC
             */
            sc->sc_imask |= HAL_INT_RXEOL | HAL_INT_RXORN;
        }
        else {
            /* Disable and then enable to satisfy the global isr enable reference counter */
            ath_hal_intrset(ah, 0);
            sc->sc_imask |= HAL_INT_RXEOL | HAL_INT_RXORN;
            ath_hal_intrset(ah, sc->sc_imask);
        }
    }
}

/*
 * This routine adds a new buffer to the free list
 * Context: Tasklet
 */
void
ath_rx_edma_requeue(ath_dev_t dev, wbuf_t wbuf)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(dev);
    struct ath_buf *bf = ATH_GET_RX_CONTEXT_BUF(wbuf);
    struct ath_rx_edma_requeue_request requeue;

    ASSERT(bf != NULL);

    ATH_RXBUF_LOCK(sc);
    /* Must synchronize with the ISR */
    requeue.sc = sc;
    requeue.bf = bf;
    OS_EXEC_INTSAFE(sc->sc_osdev, ath_rx_edma_requeue_intsafe, &requeue);
    ATH_RXBUF_UNLOCK(sc);
}

#ifdef ATH_SUPPORT_UAPSD
void
ath_rx_process_uapsd(struct ath_softc *sc, HAL_RX_QUEUE qtype, wbuf_t wbuf, struct ath_rx_status *rxs, bool isr_context)
{
    struct ieee80211_qosframe    *qwh;

    if (!sc->sc_hwuapsdtrig) {
         /* Adjust wbuf start addr to point to data, i.e skip past the RxS */ 
         qwh = (struct ieee80211_qosframe *)
             ((u_int8_t *) wbuf_raw_data(wbuf) + sc->sc_rxstatuslen);

         /* HW Uapsd trig is not supported - Process all recv frames for uapsd triggers */
         rxs->rs_isapsd = sc->sc_ieee_ops->check_uapsdtrigger(sc->sc_ieee, qwh, rxs->rs_keyix, isr_context);
    }
    else if (qtype == HAL_RX_QUEUE_HP) {
         /* Adjust wbuf start addr to point to data, i.e skip past the RxS */
         qwh = (struct ieee80211_qosframe *)
             ((u_int8_t *) wbuf_raw_data(wbuf) + sc->sc_rxstatuslen);

         /* HW Uapsd trig is supported - do uapsd processing only for HP queue */
         sc->sc_ieee_ops->uapsd_deliverdata(sc->sc_ieee, qwh, rxs->rs_keyix,
                                            rxs->rs_isapsd, isr_context);
    }
}
#endif /* ATH_SUPPORT_UAPSD */

void
ath_rx_intr(ath_dev_t dev, HAL_RX_QUEUE qtype)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(dev);
    struct ath_rx_edma *rxedma;
    wbuf_t wbuf;
    struct ath_buf *bf;
    struct ath_rx_status *rxs;
    HAL_STATUS retval;
    struct ath_hal *ah = sc->sc_ah;
    int    frames;
    rxedma = &sc->sc_rxedma[qtype];

    do {
        wbuf = rxedma->rxfifo[rxedma->rxfifoheadindex];
        if (wbuf == NULL)
            break;
        bf = ATH_GET_RX_CONTEXT_BUF(wbuf);

        /*
         * Invalidate the status bytes alone since we flush them (to clear status) 
         * after unmapping the buffer while queuing it to h/w.
         */
        OS_SYNC_SINGLE(sc->sc_osdev,
                       bf->bf_buf_addr[0], sc->sc_rxstatuslen, BUS_DMA_FROMDEVICE,
                       OS_GET_DMA_MEM_CONTEXT(bf, bf_dmacontext));
        bf->bf_status |= ATH_BUFSTATUS_SYNCED;

        rxs = bf->bf_desc;
        retval = ath_hal_rxprocdescfast(ah, NULL, 0, NULL, rxs, wbuf_raw_data(wbuf));

#ifdef ATH_RX_DESC_WAR
        if (HAL_EINVAL == retval) {
			struct ath_buf *next_bf;
			wbuf_t next_wbuf;
			u_int32_t next_idx = rxedma->rxfifoheadindex;

			bf->bf_status |= ATH_BUFSTATUS_WAR;

			INCR(next_idx, rxedma->rxfifohwsize);
			next_wbuf = rxedma->rxfifo[next_idx];

			if (next_wbuf == NULL)
				break;

			next_bf = ATH_GET_RX_CONTEXT_BUF(next_wbuf);
			next_bf->bf_status |= ATH_BUFSTATUS_WAR;
			DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s: Marking first DP 0x%x for drop\n",
				    __func__, (unsigned) bf->bf_buf_addr[0]);
			DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s: Marking second DP 0x%x for drop\n",
			        __func__, (unsigned) next_bf->bf_buf_addr[0]);
		}
#endif
        /* XXX Check for done bit in RxS */
        if (HAL_EINPROGRESS == retval) {
            break;
        }

#ifdef ATH_SUPPORT_UAPSD
#if !ATH_OSPREY_UAPSDDEFERRED
        /* Process UAPSD triggers */
        /* Skip frames with error - except HAL_RXERR_KEYMISS since
         * for static WEP case, all the frames will be marked with HAL_RXERR_KEYMISS,
         * since there is no key cache entry added for associated station in that case
         */
        if ((rxs->rs_status & ~HAL_RXERR_KEYMISS) == 0)
        {
            /* UAPSD frames being processed from ISR context */
            ath_rx_process_uapsd(sc, qtype, wbuf, rxs, true);
        }
#endif /* ATH_OSPREY_UAPSDDEFERRED */
#else
         rxs->rs_isapsd = 0;
#endif /* ATH_SUPPORT_UAPSD */

        /* add this ath_buf for deferred processing */
        TAILQ_INSERT_TAIL(&rxedma->rxqueue, bf, bf_list);

        /* clear this element before advancing */
        rxedma->rxfifo[rxedma->rxfifoheadindex] = NULL;

        /* advance the head pointer */
        INCR(rxedma->rxfifoheadindex, rxedma->rxfifohwsize);

        if (rxedma->rxfifodepth == 0)
            printk("ath_rx_intr: depth 0 PANIC\n");

        rxedma->rxfifodepth--;

    } while (TRUE);

    /*
     * remove ath_bufs from free list and add it to fifo
     */
    frames = rxedma->rxfifohwsize - rxedma->rxfifodepth;
    if (frames > 0)
        ath_rx_addbuffer(sc, qtype, frames);
}

/*
 * Helper routine for ath_rx_handler
 * Returns completed ath_buf from rxqueue (NULL if rxqueue is empty)
 * Context: ISR
\ */
struct ath_rx_get_athbuf_request {
    struct ath_rx_edma *rxedma; /* input */
    struct ath_buf *bf;         /* output (NULL if queue empty) */
};

static void ath_rxqueue_get_athbuf_intsafe(struct ath_rx_get_athbuf_request *athbuf_req)
{
    struct ath_rx_edma *rxedma = athbuf_req->rxedma;
    struct ath_buf *bf = NULL;

    bf = TAILQ_FIRST(&rxedma->rxqueue);
    if (bf) {
        TAILQ_REMOVE(&rxedma->rxqueue, bf, bf_list);
    }
    /* Return ath_buf */
    athbuf_req->bf = bf;
}

#ifdef ATH_SUPPORT_TxBF
/*
* Process H, V or CV of BeamForming 
* 0: do nothing
* 1: rx_next 
* 2: continue
*/
BF_STATUS
ath_rx_bf_handler(ath_dev_t dev,wbuf_t wbuf, struct ath_rx_status *rxs, struct ath_buf *bf)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(dev);
#if defined(ATH_SUPPORT_DFS)
    struct ath_hal *ah = sc->sc_ah;
#endif
    u_int phyerr;
    struct ieee80211_frame *wh;
    ieee80211_rx_status_t rx_status;
    u_int8_t chainreset = 0;
    struct ath_phy_stats *phy_stats = &sc->sc_phy_stats[sc->sc_curmode];

    OS_MEMZERO(&rx_status, sizeof(ieee80211_rx_status_t));
	if (sc->sc_txbfsupport==AH_FALSE){   // not bf mode
        return TX_BF_DO_NOTHING;
    }
#define Reg_MAC_PCU_H_XFER_TIMEOUT 0x831c
#define TIMEOUT_COUNT_FIELD 0xF
#define DEFAULT_TIMEOUT_VALUE 0xD
    //handle update rx_status here=================================
    if (sc->sc_rx_wbuf_waiting) {
        do {
            struct ath_rx_status rxs_tmp;

            if (!(rxs->rx_hw_upload_data)) {
                ath_rx_edma_requeue(dev, sc->sc_rx_wbuf_waiting);
                sc->sc_rx_wbuf_waiting    = NULL;
                sc->sc_bf_waiting		  = NULL;
                sc->sc_rxs_waiting		  = NULL;
                return TX_BF_DO_RX_NEXT;				
            }

            OS_MEMCPY(&rxs_tmp,sc->sc_rxs_waiting,sizeof(struct ath_rx_status));//Update its rxs
            OS_MEMCPY(sc->sc_rxs_waiting,rxs,sizeof(struct ath_rx_status));
            sc->sc_rxs_waiting->rs_more = rxs_tmp.rs_more;
            sc->sc_rxs_waiting->rs_datalen = rxs_tmp.rs_datalen;
            sc->sc_rxs_waiting->rx_hw_upload_data = 0;
        	

            if (sc->sc_rxs_waiting->rs_status != 0) {
                phy_stats->ast_rx_err++;
                if (sc->sc_rxs_waiting->rs_status & HAL_RXERR_CRC) {
                    rx_status.flags |= ATH_RX_FCS_ERROR;
                    phy_stats->ast_rx_crcerr++;
                }
                if (sc->sc_rxs_waiting->rs_status & HAL_RXERR_FIFO) {
                    phy_stats->ast_rx_fifoerr++;
                }
                if (sc->sc_rxs_waiting->rs_status & HAL_RXERR_PHY) {
                    phy_stats->ast_rx_phyerr++;
                    phyerr = sc->sc_rxs_waiting->rs_phyerr & 0x1f;
                    phy_stats->ast_rx_phy[phyerr]++;
#ifdef ATH_SUPPORT_DFS
                    {
                        u_int64_t tsf = ath_hal_gettsf64(ah);
                        /* Process phyerrs */
                        ath_process_phyerr(sc, sc->sc_bf_waiting, sc->sc_rxs_waiting, tsf);
                    }
#endif
                    ath_rx_edma_requeue(dev, sc->sc_rx_wbuf_waiting);
                    break;
                }

                if (sc->sc_rxs_waiting->rs_status & HAL_RXERR_DECRYPT) {
                    /*
                     * Decrypt error. We only mark packet status here
                     * and always push up the frame up to let NET80211 layer
                     * handle the actual error case, be it no decryption key
                     * or real decryption error.
                     * This let us keep statistics there.
                     */
                    phy_stats->ast_rx_decrypterr++;
                    rx_status.flags |= ATH_RX_DECRYPT_ERROR;
                } else if (sc->sc_rxs_waiting->rs_status & HAL_RXERR_MIC) {
                    phy_stats->ast_rx_demicerr++;
                    rx_status.flags |= ATH_RX_MIC_ERROR;
                } else {
                    phy_stats->ast_rx_demicok++;
                }

                /*
                 * Reject error frames with the exception of decryption, MIC,
                 * and key-miss failures.
                 * For monitor mode, we also ignore the CRC error.
                 */
                if (sc->sc_opmode == HAL_M_MONITOR) {
                    if (sc->sc_rxs_waiting->rs_status &
                        ~(HAL_RXERR_DECRYPT | HAL_RXERR_MIC |
                          HAL_RXERR_KEYMISS | HAL_RXERR_CRC)) {
                              ath_rx_edma_requeue(dev, sc->sc_rx_wbuf_waiting);
                              break;
                    }
                } else {
                    if (sc->sc_rxs_waiting->rs_status &
                        ~(HAL_RXERR_DECRYPT | HAL_RXERR_MIC | HAL_RXERR_KEYMISS)) {
                            ath_rx_edma_requeue(dev, sc->sc_rx_wbuf_waiting);
                            break;
                    }
                }
            }		

            //set H or V/CV status to be zero
            OS_MEMCPY(&rxs_tmp, rxs, sizeof(struct ath_rx_status));
            OS_MEMZERO(rxs, sizeof(struct ath_rx_status));
            rxs->rs_datalen = rxs_tmp.rs_datalen;
            rxs->rx_hw_upload_data = rxs_tmp.rx_hw_upload_data;
            rxs->rx_hw_upload_data_valid = rxs_tmp.rx_hw_upload_data_valid;
            rxs->rx_hw_upload_data_type = rxs_tmp.rx_hw_upload_data_type;
            
            sc->last_rx_type = 0;
            wbuf_init(sc->sc_rx_wbuf_waiting, (sc->sc_rxs_waiting->rs_datalen + sc->sc_rxstatuslen));
            wbuf_pull(sc->sc_rx_wbuf_waiting, sc->sc_rxstatuslen);
            wh = (struct ieee80211_frame *)wbuf_header(sc->sc_rx_wbuf_waiting) ;
            ath_rx_process(sc, sc->sc_bf_waiting, sc->sc_rxs_waiting, wh->i_fc[0], &rx_status, &chainreset);
            OS_MEMZERO(&rx_status,sizeof(ieee80211_rx_status_t));
        
        } while (0);

        sc->sc_rx_wbuf_waiting   = NULL;
        sc->sc_bf_waiting		  = NULL;
        sc->sc_rxs_waiting		  = NULL;
        
        if (rxs->rs_status != 0) {
            if (!rxs->rx_hw_upload_data_valid) {
                u_int32_t val;
                sc->last_h_invalid = 1;
                //Workaround for HW issue EV [69449] Chip::Osprey HW does not filter non-directed frame for uploading TXBF delay report
                val = OS_REG_READ(sc->sc_ah, Reg_MAC_PCU_H_XFER_TIMEOUT);
                val = ((val-0x1)&TIMEOUT_COUNT_FIELD) + (val& (~TIMEOUT_COUNT_FIELD));
                OS_REG_WRITE(sc->sc_ah, Reg_MAC_PCU_H_XFER_TIMEOUT, val);
            }
            return TX_BF_DO_RX_NEXT;
        }
    }//end of (sc->sc_rx_wbuf_waiting)
    
    if (rxs->rs_more) {
        //Handle the rs_more Frame
        sc->sc_rx_wbuf_waiting  = wbuf;
        sc->sc_bf_waiting       = bf;
        sc->sc_rxs_waiting      = rxs;
        return TX_BF_DO_CONTINUE;
    }


    if (sc->last_rx_type!=0) {
        if (rxs->rx_hw_upload_data==0) {
            //the expected H after rx_more not come
            sc->last_rx_type=0;
            return TX_BF_DO_RX_NEXT;
        } else {
            DPRINTF(sc, ATH_DEBUG_ANY,"%s :Store the CSI_1 of is_h Datalen(%d),h vaild (%d)\n",__FUNCTION__,rxs->rs_datalen,rxs->rx_hw_upload_data_valid); //hcl
            
            if (rxs->rx_hw_upload_data_valid) {
                wbuf_init(wbuf, (rxs->rs_datalen + sc->sc_rxstatuslen));
                wbuf_pull(wbuf, sc->sc_rxstatuslen);
                wh = (struct ieee80211_frame *)wbuf_header(wbuf);  

                //UPLOAD the H to next level
                ath_rx_process(sc, bf, rxs, wh->i_fc[0], &rx_status, &chainreset);
                //Workaround for HW issue EV [69449] Chip::Osprey HW does not filter non-directed frame for uploading TXBF delay report
                if(sc->last_h_invalid) {
                    u_int32_t val;
                    
                    val = OS_REG_READ(sc->sc_ah, Reg_MAC_PCU_H_XFER_TIMEOUT);
	                val = DEFAULT_TIMEOUT_VALUE + (val& (~TIMEOUT_COUNT_FIELD));
	                OS_REG_WRITE(sc->sc_ah, Reg_MAC_PCU_H_XFER_TIMEOUT, val);
                }
                sc->last_h_invalid = 0;
                return TX_BF_DO_CONTINUE;
            } else {
                u_int32_t val;
                
                sc->last_h_invalid = 1;
                //Workaround for HW issue EV [69449] Chip::Osprey HW does not filter non-directed frame for uploading TXBF delay report
                val = OS_REG_READ(sc->sc_ah, Reg_MAC_PCU_H_XFER_TIMEOUT);
                val = ((val-0x1)&TIMEOUT_COUNT_FIELD) + (val& (~TIMEOUT_COUNT_FIELD));
                OS_REG_WRITE(sc->sc_ah, Reg_MAC_PCU_H_XFER_TIMEOUT, val);         
                sc->last_rx_type = 0;
                return TX_BF_DO_RX_NEXT;
            }
        }
    }//end of (sc->last_rx_type!=0)
    return TX_BF_DO_NOTHING;
}
#endif

/*
 * Process receive queue, as well as LED, etc.
 * Arg "flush":
 * 0: Process rx frames in rx interrupt.
 * 1: Drop rx frames in flush routine.
 * 2: Flush and indicate rx frames, must be synchronized with other flush threads.
 */
static int
ath_rx_handler(ath_dev_t dev, int flush, HAL_RX_QUEUE qtype)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(dev);
    struct ath_rx_edma *rxedma;
    struct ath_buf *bf;
#if defined(ATH_SUPPORT_DFS) || defined(ATH_SUPPORT_SPECTRAL)
    struct ath_hal *ah = sc->sc_ah;
#endif
    struct ath_rx_status *rxs;
    void *ds;
    u_int phyerr;
    struct ieee80211_frame *wh;
    wbuf_t wbuf = NULL;
    ieee80211_rx_status_t rx_status;
    struct ath_phy_stats *phy_stats = &sc->sc_phy_stats[sc->sc_curmode];
    u_int8_t chainreset = 0;
    int rx_processed = 0;
    struct ath_rx_get_athbuf_request athbuf_req;

#if ATH_OSPREY_RXDEFERRED
    // Retrieve completed receive buffers from HW. 
    ath_rx_intr(dev, qtype);
#endif // ATH_PROCESS_OSPREY_RX_IN_DPC

    rxedma = &sc->sc_rxedma[qtype];
    athbuf_req.rxedma = rxedma;
    
    DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s\n", __func__);
    do {
        /* If handling rx interrupt and flush is in progress => exit */
        if (sc->sc_rxflush && (flush == RX_PROCESS)) {
            break;
        }

        /* Get completed ath_buf from rxqueue. Must synchronize with the ISR */
        ATH_RXQ_LOCK(rxedma);
        OS_EXEC_INTSAFE(sc->sc_osdev, ath_rxqueue_get_athbuf_intsafe, &athbuf_req); 
        ATH_RXQ_UNLOCK(rxedma);
        bf = athbuf_req.bf;
        if (bf == NULL) {
            break;
        }

        wbuf = bf->bf_mpdu;
        if (wbuf == NULL) {		/* XXX ??? can this happen */
            printk("no mpdu (%s)\n", __func__);
            continue;
        }
        ++rx_processed;

        rxs = (struct ath_rx_status *)(bf->bf_desc);

        /*
         * Save RxS location for packetlog.
         */
        ds = (void *)wbuf_raw_data(wbuf);

#ifdef ATH_RX_DESC_WAR
		if (bf->bf_status & ATH_BUFSTATUS_WAR) {
			DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s: Dropping DP 0x%x\n",
                __func__, (unsigned) bf->bf_buf_addr[0]);
            goto rx_next;
		}
#endif

        /* Force PPM tracking */
        ath_force_ppm_logic(&sc->sc_ppm_info, bf, HAL_OK, rxs /*XXX */);

#ifdef AR_DEBUG
        if (sc->sc_debug & ATH_DEBUG_RECV_DESC)
            ath_printrxbuf(bf, 1);
#endif

        if (flush == RX_DROP) {
            /*
             * If we're asked to flush receive queue, directly
             * chain it back at the queue without processing it.
             */
            goto rx_next;
        }

        OS_MEMZERO(&rx_status, sizeof(ieee80211_rx_status_t));

        /* point to the beginning of actual frame */
        bf->bf_vdata = (void *)((u_int8_t *)ds + sc->sc_rxstatuslen);

#ifndef REMOVE_PKT_LOG
        /* do pktlog */
        {
            struct log_rx log_data;
            log_data.ds = ds;
            log_data.status = rxs;
            log_data.bf = bf;
            ath_log_rx(sc, &log_data, 0);
        }
#endif

#ifdef ATH_SUPPORT_TxBF
        {//Check if Have H, V/CV upload from HW
            int next_do = ath_rx_bf_handler(dev, wbuf, rxs, bf);
            
            if (next_do == TX_BF_DO_RX_NEXT) {
                goto rx_next;
            } else if (next_do == TX_BF_DO_CONTINUE) {
                continue;
            }
        }
#endif

        if (rxs->rs_status == 0) {
            
            if (rxs->rs_more) {

#if USE_MULTIPLE_BUFFER_RCV
                        /*
                         * Frame spans multiple descriptors; save
                         * it for the next completed descriptor, it
                         * will be used to construct a jumbogram.
                         */
                if (sc->sc_rxpending != NULL) {
                    /* Max frame size is currently 2 clusters, So if we get a 2nd one with More to follow, discard the first */
                    DPRINTF(sc, ATH_DEBUG_ANY,
                            "%s: already a pending wbuf %p len = %d n",
                            __func__, sc->sc_rxpending, rxs->rs_datalen);

                    phy_stats->ast_rx_toobig++;
                    goto rx_next;
                }

                // Set RxPending to Wbuf - hopefully, the next one will complete the chain.
                sc->sc_rxpending = wbuf;
                // Set the length. Packet length will be set when the 2nd buffer is processed.
                wbuf_init(sc->sc_rxpending, (rxs->rs_datalen + sc->sc_rxstatuslen));
                continue;
#else /* !USE_MULTIPLE_BUFFER_RCV */
                        /*
                         * Frame spans multiple descriptors; this
                         * cannot happen yet as we don't support
                         * jumbograms.    If not in monitor mode,
                         * discard the frame.
                         */
#ifndef ERROR_FRAMES
                        /*
                         * Enable this if you want to see
                         * error frames in Monitor mode.
                         */
        
                //printk("rx_tasklet: received frames with MORE set in rx_status\n");
                goto rx_next;
                /* fall thru for monitor mode handling... */
#endif // ERROR_FRAMES
#endif /* USE_MULTIPLE_BUFFER_RCV */


            } 
#if USE_MULTIPLE_BUFFER_RCV
            else if (sc->sc_rxpending != NULL) {
                /*
                 * This is the second part of a jumbogram,
                 * chain it to the first wbuf, adjust the
                 * frame length, and clear the rxpending state.
                 */
                wbuf_setnextpkt(sc->sc_rxpending, wbuf);
                // Set the start pointer and length of the buffer for the 2nd one in the chain. Skip the status. We wont init it later. 
                wbuf_pull(wbuf, sc->sc_rxstatuslen);
                wbuf_init(wbuf, rxs->rs_datalen);
                // Switch the wbuf to the pending one : we've chained them and now ready to indicate.
                bf->bf_mpdu = wbuf = sc->sc_rxpending;
                // Prep for the next "more" handling.
                sc->sc_rxpending = NULL;
                // Skip the wbuf_init. We have already setup the length correctly and dont want anything overwritten.
                goto skip_wbuf_init;
            }  
#endif /* USE_MULTIPLE_BUFFER_RCV */
        }
        else { // if (rxs->rs_status != 0)
            phy_stats->ast_rx_err++;
            if (rxs->rs_status & HAL_RXERR_CRC) {
                rx_status.flags |= ATH_RX_FCS_ERROR;
                phy_stats->ast_rx_crcerr++;
            }
            if (rxs->rs_status & HAL_RXERR_FIFO)
                phy_stats->ast_rx_fifoerr++;
            if (rxs->rs_status & HAL_RXERR_PHY) {
                phy_stats->ast_rx_phyerr++;
                phyerr = rxs->rs_phyerr & 0x1f;
                phy_stats->ast_rx_phy[phyerr]++;
#ifdef ATH_SUPPORT_DFS
                {
                    u_int64_t tsf = ath_hal_gettsf64(ah);
                    /* Process phyerrs */
                    ath_process_phyerr(sc, bf, rxs, tsf);
                }
#endif

#if ATH_SUPPORT_SPECTRAL
                {
                    u_int64_t tsf = ath_hal_gettsf64(ah);
                    if (is_spectral_phyerr(sc, bf, rxs)) {
                        SPECTRAL_LOCK(sc->sc_spectral);
                        ath_process_spectraldata(sc, bf, rxs, tsf);
                        SPECTRAL_UNLOCK(sc->sc_spectral);          
                    }

                }
#endif  /* ATH_SUPPORT_SPECTRAL */

                goto rx_next;
            }

            if (rxs->rs_status & HAL_RXERR_DECRYPT) {
                /*
                 * Decrypt error. We only mark packet status here
                 * and always push up the frame up to let NET80211 layer
                 * handle the actual error case, be it no decryption key
                 * or real decryption error.
                 * This let us keep statistics there.
                 */
                 phy_stats->ast_rx_decrypterr++;
                rx_status.flags |= ATH_RX_DECRYPT_ERROR;
            } else if (rxs->rs_status & HAL_RXERR_MIC) {
#if 0
                /*
                 * Demic error. We only mark frame status here
                 * and always push up the frame up to let NET80211 layer
                 * handle the actual error case.
                 * This let us keep statistics there and also apply the
                 * WAR for bug 6903: (Venice?) Hardware may
                 * post a false-positive MIC error.  Need to expose this
                 * error to tkip_demic() to really declare a failure.
                 */
                if ((frame_fc0 & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL) {
                    /*
                     * As doc. in hardware bug 30127, sometimes, we get invalid
                     * MIC failures on valid control frames. Remove these mic errors.
                     */
                    ds->ds_rxstat.rs_status &= ~HAL_RXERR_MIC;
                    phy_stats->ast_rx_demicok++;
                }
                else {
#endif
                    phy_stats->ast_rx_demicerr++;
                    rx_status.flags |= ATH_RX_MIC_ERROR;
#if 0
                }
#endif
            } else {
                phy_stats->ast_rx_demicok++;
            }

            /*
             * Reject error frames with the exception of decryption, MIC,
             * and key-miss failures.
             * For monitor mode, we also ignore the CRC error.
             */
            if (sc->sc_opmode == HAL_M_MONITOR) {
                if (rxs->rs_status &
                    ~(HAL_RXERR_DECRYPT | HAL_RXERR_MIC |
                      HAL_RXERR_KEYMISS | HAL_RXERR_CRC))
                    goto rx_next;
            } else {
                if (rxs->rs_status &
                    ~(HAL_RXERR_DECRYPT | HAL_RXERR_MIC | HAL_RXERR_KEYMISS)) {
                    goto rx_next;
                } else {
                    if (rxs->rs_status & HAL_RXERR_KEYMISS) {
                        rx_status.flags |= ATH_RX_KEYMISS;
                    }
                }
            }
        }

#ifdef ATH_SUPPORT_UAPSD
#if ATH_OSPREY_UAPSDDEFERRED
        /* ignore flushed frames (RX_DROP) */
        if ((flush == RX_PROCESS) || (flush == RX_FORCE_PROCESS)) {
            /* Process UAPSD triggers */
            /* Skip frames with error - except HAL_RXERR_KEYMISS since
             * for static WEP case, all the frames will be marked with HAL_RXERR_KEYMISS,
             * since there is no key cache entry added for associated station in that case
             */
            if ((rxs->rs_status & ~HAL_RXERR_KEYMISS) == 0)
            {
                /* UAPSD frames being processed outside ISR context */
                ath_rx_process_uapsd(sc, qtype, wbuf, rxs, false);
            }
        }
#endif /* ATH_OSPREY_UAPSDDEFERRED */
#endif /* ATH_SUPPORT_UAPSD */

        /*
         * Initialize wbuf; the length includes packet length
         * and status length. The status length later deducted
         * from the total len by the wbuf_pull
         */
        wbuf_init(wbuf, (rxs->rs_datalen + sc->sc_rxstatuslen));
#if USE_MULTIPLE_BUFFER_RCV
skip_wbuf_init:
#endif

        /*
         * Adjust wbuf start addr to point to data, i.e skip past the RxS.
         */
        wbuf_pull(wbuf, sc->sc_rxstatuslen);

        wh = (struct ieee80211_frame *)wbuf_header(wbuf);
        ath_rx_process(sc, bf, rxs, wh->i_fc[0], &rx_status, &chainreset);

        /*
         * For frames successfully indicated, the buffer will be
         * returned to us by upper layers by calling ath_rx_mpdu_requeue,
         * either synchronusly or asynchronously.
         * So we don't want to do it here in this loop.
         */
        continue;

rx_next:
#if USE_MULTIPLE_BUFFER_RCV
        if (sc->sc_rxpending) {
            // We come to rx_next whenever we have packet errors of any kind.
            // It's now safe to requeue a pending packet...
            ath_rx_edma_requeue(dev, sc->sc_rxpending);
            sc->sc_rxpending = NULL;
            sc->sc_bfpending = NULL;
        }
#endif /* USE_MULTIPLE_BUFFER_RCV */
    
        ath_rx_edma_requeue(dev, wbuf);
    } while (TRUE);

#ifdef ATH_SUPPORT_DFS
    if (sc->sc_dfs != NULL) {
        if (!STAILQ_EMPTY(&sc->sc_dfs->dfs_arq))
            dfs_process_ar_event(sc, &sc->sc_curchan);
        if (!STAILQ_EMPTY(&sc->sc_dfs->dfs_radarq)) {
            sc->sc_rtasksched = 1;
            OS_SET_TIMER(&sc->sc_dfs->sc_dfs_task_timer, 0);
        }
    }
#endif
#ifdef notyet
    /* rx signal state monitoring */
    ath_hal_rxmonitor(ah, &sc->sc_halstats, &sc->sc_curchan);
#endif

#ifdef ATH_ADDITIONAL_STATS
    if (rx_processed < ATH_RXBUF ) {
        sc->sc_stats.ast_pkts_per_intr[rx_processed]++;
    }
    else {
        sc->sc_stats.ast_pkts_per_intr[ATH_RXBUF]++;
    }
#else
#endif

    if (chainreset) {
        printk("Reset rx chain mask. Do internal reset. (%s)\n", __func__);
        ASSERT(flush == 0);
        ath_internal_reset(sc);
    }

    return 0;
}

void
ath_rx_edma_intr(ath_dev_t dev, HAL_INT status, int *sched)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(dev);
    struct ath_hal *ah = sc->sc_ah;

    if (status & HAL_INT_RXORN) {
        sc->sc_stats.ast_rxorn++;
    }
    if (status & HAL_INT_RXEOL) {
        sc->sc_stats.ast_rxeol++;
    }
    if (status & (HAL_INT_RXHP | HAL_INT_RXEOL | HAL_INT_RXORN)) {
        ath_rx_intr(dev, HAL_RX_QUEUE_HP);
        *sched = ATH_ISR_SCHED;
    }
    if (status & (HAL_INT_RXLP | HAL_INT_RXEOL | HAL_INT_RXORN)) {
        ath_rx_intr(dev, HAL_RX_QUEUE_LP);
        *sched = ATH_ISR_SCHED;
    }

    /* Check if RXEOL condition was resolved */
    if (status & HAL_INT_RXEOL) {
        /* TODO - check rx fifo threshold here */
        if (sc->sc_rxedma[HAL_RX_QUEUE_HP].rxfifodepth == 0 || 
            sc->sc_rxedma[HAL_RX_QUEUE_LP].rxfifodepth == 0) {
            /* No buffers available - disable RXEOL/RXORN to avoid interrupt storm 
             * Disable and then enable to satisfy global isr enable reference counter 
             */
            ; //For further investigation
        }
        //BUG EV# 66955 Interrupt storm fix
        //Interrup bits must be cleared
        ath_hal_intrset(ah, 0);
        sc->sc_imask &= ~(HAL_INT_RXEOL | HAL_INT_RXORN);
        ath_hal_intrset(ah, sc->sc_imask);
    }
}

/*
 * Process received frames in both high and low priority
 * queues.
 */
int
ath_rx_edma_tasklet(ath_dev_t dev, int flush)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(dev);

    sc->sc_edmarxdpc = 1;

    ath_rx_handler(dev, flush, HAL_RX_QUEUE_HP);

    ath_rx_handler(dev, flush, HAL_RX_QUEUE_LP);

    sc->sc_edmarxdpc = 0;

    return 0;
}

#ifdef AR_DEBUG
static void ath_dump_rx_que_desc( struct ath_softc *sc, HAL_RX_QUEUE qtype)
{
    //struct ath_rx_get_athbuf_request athbuf_req;
    struct ath_rx_edma *rxedma = &sc->sc_rxedma[qtype];
    int i = 0;

    DPRINTF(sc, ATH_DEBUG_ANY, "%s[%d]: rxedma->rxfifohwsize %d, rxedma->rxfifodepth %d rxedma->rxfifoheadindex %d, rxedma->rxfifotailindex %d\n",__func__,__LINE__,
        rxedma->rxfifohwsize, rxedma->rxfifodepth, rxedma->rxfifoheadindex, rxedma->rxfifotailindex);
    
    for( i = 0; i < rxedma->rxfifohwsize; i++)
    {
        DPRINTF(sc, ATH_DEBUG_ANY, "%s[%d]: RX[%d]rxedma->rxfifo[%d] %p\n",__func__,__LINE__,
            qtype, i, rxedma->rxfifo[i]);
        
    }

}
void ath_dump_rx_edma_desc(ath_dev_t dev)
{
    struct ath_softc *sc = ATH_DEV_TO_SC(dev);
    DPRINTF(sc, ATH_DEBUG_ANY, "%s[%d]: sc->sc_rxlink %p sc->sc_rxpending %p\n",__func__,__LINE__,sc->sc_rxlink, sc->sc_rxpending);
    ath_dump_rx_que_desc(sc, HAL_RX_QUEUE_HP);
    ath_dump_rx_que_desc(sc, HAL_RX_QUEUE_LP);
}
#endif /* AR_DEBUG */

#endif /* ATH_SUPPORT_EDMA */
