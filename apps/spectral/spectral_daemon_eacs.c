#include "spectral_defs.h"

int avg_chan_load;
int num_scan_reports;
int tstamp_start_higher_load=0;
int tstamp_stop_higher_load=0;
int global_cload_timeout=10000000;

void start_eacs_scan(void)
{
    char sys_cmd[128];
    stop_eacs_monitor_scan();
    sprintf(sys_cmd, "ifconfig %s down; iwconfig %s channel 0; ifconfig %s up", global_vap, global_vap, global_vap);
    system(sys_cmd);
}

int is_dynamic_chan_change_reqd(int chan_load, int tstamp)
{

        if (chan_load > avg_chan_load) {
            if (tstamp_start_higher_load > 0) {
                 if ((tstamp - tstamp_start_higher_load) > global_cload_timeout) {
                    SPECTRAL_DPRINTF(ATH_DEBUG_SPECTRAL2,"%s chan_load=%d num_scan_reports=%d tstamp=%d tstamp_start_higher_load=%d global_cload_timeout=%d\n", __func__, chan_load, num_scan_reports, tstamp, tstamp_start_higher_load, global_cload_timeout);              
                      return 1;
                }
            }
            if (tstamp_start_higher_load == 0)
                tstamp_start_higher_load = tstamp;
        } else 
                tstamp_start_higher_load = 0;

        if (avg_chan_load)
            avg_chan_load = (avg_chan_load * num_scan_reports);
        avg_chan_load += chan_load;
        num_scan_reports++;
        avg_chan_load /= num_scan_reports;
        SPECTRAL_DPRINTF(ATH_DEBUG_SPECTRAL2,"%s tstamp=%d avg_chan_load=%d chan_load=%d num_scan_reports=%d tstamp_start_higher_load=%d\n", __func__, tstamp, avg_chan_load, chan_load, num_scan_reports, tstamp_start_higher_load);
        return 0;
}
int is_interference_detected(struct ss *bd)
{
        return (bd->count_cwa > 0);
}

void start_eacs_monitor_scan(void)
{
    char sys_cmd[128];
    avg_chan_load=30; num_scan_reports=0; tstamp_start_higher_load=0;
    sprintf(sys_cmd, "spectraltool -i %s startscan", global_radio);
    system(sys_cmd);
}

void stop_eacs_monitor_scan(void)
{
    char sys_cmd[128];
    sprintf(sys_cmd, "spectraltool -i %s stopscan", global_radio);
    system(sys_cmd);
}

