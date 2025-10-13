#ifdef HARD

#include "nrf_cc3xx_platform.h"

void crypto_hw_init(void) {
    (void)nrf_cc3xx_platform_init();
}

#endif
