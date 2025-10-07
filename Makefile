override export KAT_RNG := 0

$(info TARGET(raw)="$(TARGET)" origin=$(origin TARGET))

.DEFAULT_GOAL := all
.PHONY: all where

where:
	@pwd
	@echo NRFXLIB_DIR=$(NRFXLIB_DIR)
	@find $(NRFXLIB_DIR) -maxdepth 7 -type f \
	  \( -name 'libmbedcrypto*.a' -o -name 'libnrf_cc310*.a' -o -name 'libnrf_cc310_platform*.a' \) -print


# ===== nRF nrfxlib (CC31x) autodetect: headers + libs =====
NRFXLIB_DIR ?= $(abspath third_party/nrfxlib)

# clean help ci-run 以外一律要指定 TARGET
ifeq (,$(filter clean help ci-run%,$(MAKECMDGOALS)))

ifeq ($(strip $(TARGET)),)
$(error TARGET is required, ex. make TARGET=nrf52840)
endif

# nrfxlib/crypto is required
ifeq ("$(wildcard $(NRFXLIB_DIR)/crypto)","")
$(error FATAL: nrfxlib not found at $(NRFXLIB_DIR))
endif

endif

# clean help ci-run 以外一律要指定 TARGET
ifeq (,$(filter clean help ci-run%,$(MAKECMDGOALS)))
ifeq ($(strip $(TARGET)),)
$(error TARGET is required, ex. make TARGET=nrf52840)
endif
endif

CC := arm-none-eabi-gcc

LDLIBS := 

ifeq ($(TARGET),x86)
  PLATFORM := platforms/x86
  CC := gcc
  CFLAGS := -O3 -std=c11 -Wall -Wextra -Wpedantic -ffunction-sections \
            -fdata-sections -mrdrnd -Wl,--gc-sections
  STARTUP :=                         # like platform/x86/startup.c
  LDS  :=                            # like platform/x86/linker.ld
  OBJCOPY := objcopy
  SIZE := size
  ELF := sign_x86.elf

else ifeq ($(strip $(TARGET)),nrf52840)
  $(info HIT nrf52840)
  PLATFORM := platforms/nrf52840
  STARTUP := $(PLATFORM)/startup.c
  LDS  := $(PLATFORM)/linker.ld
  ARCHFLAGS := -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
  CFLAGS := -O2 -ffreestanding -Wall -Wextra 
  #CFLAGS += -I$(NRFXLIB_DIR)/crypto/nrf_oberon/include
  ELF := sign_nrf52840.elf
  LIB_CC310 := $(firstword \
    $(wildcard $(NRFXLIB_DIR)/crypto/nrf_cc310/lib/cortex-m4/hard-float/armgcc/libnrf_cc310*.a) \
    $(wildcard $(NRFXLIB_DIR)/crypto/nrf_cc310/lib/cortex-m4/hard-float/libnrf_cc310*.a))
  LIB_CC310_PLAT := $(firstword \
    $(wildcard $(NRFXLIB_DIR)/crypto/nrf_cc310_platform/lib/cortex-m4/hard-float/armgcc/libnrf_cc310_platform*.a) \
    $(wildcard $(NRFXLIB_DIR)/crypto/nrf_cc310_platform/lib/cortex-m4/hard-float/libnrf_cc310_platform*.a))
  #LIB_MBEDCRYPTO := $(firstword \
  #  $(wildcard $(NRFXLIB_DIR)/crypto/nrf_security/lib/cortex-m4/hard-float/armgcc/libmbedcrypto*.a) \
  #  $(wildcard $(NRFXLIB_DIR)/crypto/nrf_security/lib/cortex-m4/hard-float/libmbedcrypto*.a))
  ARCH_DIR   := cortex-m4
  FLOAT_DIR  := soft-float
  LIB_MBEDCRYPTO := $(firstword \
    $(wildcard $(NRFXLIB_DIR)/crypto/nrf_security/lib/$(ARCH_DIR)/$(FLOAT_DIR)/armgcc/libmbedcrypto*.a) \
    $(wildcard $(NRFXLIB_DIR)/crypto/nrf_security/lib/$(ARCH_DIR)/$(FLOAT_DIR)/libmbedcrypto*.a))
  RESC := run_sign.resc
  MAP_FILE := sign_nrf52840.map

else ifeq ($(TARGET),nrf5340dk)
  PLATFORM := platforms/nrf5340dk
  STARTUP := $(PLATFORM)/startup.c
  LDS  := $(PLATFORM)/linker.ld
  ARCHFLAGS := -mcpu=cortex-m33 -mthumb -mfloat-abi=soft
  CFLAGS := -O2 -ffreestanding -Wall -Wextra 
  ARCH_DIR   := cortex-m33+nodsp
  FLOAT_DIR  := soft-float
  ELF       := sign_nrf5340dk.elf
  RESC := ./ci/renode/run_sign_nrf5340dk.resc
  MAP_FILE := sign_nrf5340dk.map

endif

# print folder in platforms
#$(foreach d,$(notdir $(wildcard $(dir $(abspath $(lastword $(MAKEFILE_LIST))))platforms/*)),$(if $(wildcard $(dir $(abspath $(lastword $(MAKEFILE_LIST))))platforms/$(d)/.),$(info $(d))))

$(info NRFXLIB_DIR = $(NRFXLIB_DIR))

NM ?= $(shell $(CC) -print-prog-name=nm)

ifneq ($(NRF_CC_BACKEND),)
CFLAGS += -I$(NRFXLIB_DIR)/crypto/$(NRF_CC_BACKEND)/include
endif

CFLAGS += -Ithird_party/mbedtls/include

# Only use KAT rng.c when make KAT_RNG=1
ifeq ($(KAT_RNG),1)
  RNG_SRC := kat/rng.c kat/kat_rng.c kat/aes256.c
  CFLAGS  += -DKAT_RNG
endif

OBJS := addr_compressed.o thf.o common.o addr.o  \
        chain.o base_2b.o uart_min.o \
        keygen.o sha256.o slh_dsa_sign.o trng.o \
        wots_plus.o fors_sign.o \
        psa_crypto.o rng.o aes256.o 

#OBJS += xmss_sign.o

RENODE_IMG = renode_pinned:cached

WORKDIR     ?= $(shell pwd)

#RNG_OBJS := $(RNG_SRC:.c=.o)

aes256.o: kat/aes256.c
	$(CC) $(ARCHFLAGS) $(CFLAGS) -c $< -o $@  

rng.o: kat/rng.c
	$(CC) $(ARCHFLAGS) $(CFLAGS) -c $< -o $@  

psa_crypto.o: library/psa_crypto.c
	$(CC) $(ARCHFLAGS) $(CFLAGS) -c $< -o $@

OBERON_LIB := $(NRFXLIB_DIR)/crypto/nrf_oberon/lib/$(strip $(ARCH_DIR))/$(strip $(FLOAT_DIR))/liboberon_3.0.17.a

#LDFLAGS := -specs=nosys.specs -specs=nano.specs -Wl,-u,memcpy -Wl,-u,__aeabi_memcpy 
    #       -Wl,--gc-sections \
    #       -T $(LDS) -Wl,-Map,$(MAP_FILE) \
    #       -Wl,--start-group -lc_nano -lgcc -lm -Wl,--end-group \
    #       -Lthird_party/mbedtls/library \
    #          -Wl,--start-group \
    #            -Wl,--whole-archive \
    #               -lmbedtls -lmbedx509 -lmbedcrypto  \
    #            -Wl,--no-whole-archive \
    #          -Wl,--end-group 

%.o: %.c
	$(CC) $(ARCHFLAGS) $(CFLAGS) -c $^ -o $@

NRFXLIB_DIR := third_party/nrfxlib

ifneq ($(filter clean,$(MAKECMDGOALS)),)
  # do nothing
else
  $(info NRFXLIB_DIR = $(NRFXLIB_DIR))
  $(info NRF_CC_BACKEND = $(NRF_CC_BACKEND))
#  $(info RNG_SRC = $(RNG_SRC))
#  $(info RNG_OBJS = $(RNG_OBJS))

endif

$(info KAT_RNG = $(KAT_RNG))
$(info TARGET = $(TARGET))
$(info MAP_FILE = $(MAP_FILE))


all: sign.elf

sha256.o: platforms/sha256.c
	$(CC) $(CFLAGS) -c $< -o $@

sign.elf:  $(LDS) $(OBJS) $(RNG_OBJS) $(PSA_CRYPTO_OBJS)
	$(CC) $(ARCHFLAGS) -Ithird_party/mbedtls/include main.c $(STARTUP) $(OBJS) $(RNG_OBJS) $(PSA_CRYPTO_OBJS) -v $(OBERON_LIB) $(LDFLAGS) $(LIBDIRS) -o $(ELF)
	$(NM) $(ELF) | grep -E 'memcpy|__aeabi_memcpy'

clean:
	rm -f *.o sign_*.elf sign.elf
	rm -f $(ELF)

# 本機（有裝 renode）
run: $(ELF) $(RESC)
	renode -e 'include @$(RESC); sleep 2; q'

RENODE  ?= ./renode_portable/renode

strip_ansi = sed 's/\x1B\[[0-9;]*[A-Za-z]//g'

ci-run-nrf52840: $(ELF) $(RESC)
	@echo "CFLAGS += -I$(NRFXLIB_DIR)/crypto/nrf_cc310_bl/include" \
		$(if $(NRF_CC_BACKEND), " -I$(NRFXLIB_DIR)/crypto/$(NRF_CC_BACKEND)/include")
	@echo "NRF_LIBS:" && printf "  %s\n" $(NRF_LIBS)
	$(RENODE) --console --disable-xwt \
		-e "set ansi false; include @$(RESC); sleep 2; q" \
		| $(strip_ansi)

ci-run-nrf5340dk: $(ELF) $(RESC)
	@echo "CFLAGS += $(if $(NRF_CC_BACKEND), " -I$(NRFXLIB_DIR)/crypto/$(NRF_CC_BACKEND)/include")"
	@echo "NRF_LIBS:" && printf "  %s\n" $(NRF_LIBS)
	$(RENODE) --console --disable-xwt -e 'help; q' | grep -i UART | sed 's/\x1B\[[0-9;]*[A-Za-z]//g'
	$(RENODE) --console --disable-xwt \
		-e "set ansi false; include @$(RESC); sleep 2; q" \
		| $(strip_ansi)
