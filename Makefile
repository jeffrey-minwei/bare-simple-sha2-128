override export KAT := 0

.DEFAULT_GOAL := all
.PHONY: all

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

OBJS := addr_compressed.o thf.o common.o addr.o chain.o base_2b.o keygen.o sha256.o slh_dsa_sign.o fors_sign.o fors_sk_gen.o

OBJS += xmss_sign.o psa_crypto.o

CC := arm-none-eabi-gcc

ifeq ($(TARGET),x86)
  PLATFORM := platforms/x86
  CC := gcc
  CFLAGS := -O3 -std=c11 -Wall -Wextra -Wpedantic -ffunction-sections -fdata-sections -mrdrnd -Wl,--gc-sections
  LDFLAGS := -Wl,-Map,x86_sign.map
  STARTUP :=                         # like platform/x86/startup.c
  LDS  :=                            # like platform/x86/linker.ld
  OBJCOPY := objcopy
  SIZE := size
  ELF := sign_x86.elf

else ifeq ($(TARGET),nrf52840)
  PLATFORM := platforms/nrf52840
  STARTUP := $(PLATFORM)/startup.c
  LDS  := $(PLATFORM)/linker.ld
  CFLAGS := -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -mfpu=fpv4-sp-d16 -O2 \
            -ffreestanding -Wall -Wextra \
            -DCRYPTO_BACKEND_CC310_BL -Wl,--gc-sections \
            -I$(NRFXLIB_DIR)/crypto/nrf_cc310_bl/include \
            -I$(NRFXLIB_DIR)/crypto/nrf_cc310_mbedcrypto/include \
            -I$(NRFXLIB_DIR)/crypto/nrf_oberon/include
  LDFLAGS := -T $(LDS) -Wl,-Map,sign_nrf52840.map -Wl,--whole-archive \
             -Wl,--no-whole-archive -specs=nano.specs -nostartfiles
  ELF := sign_nrf52840.elf
  # NRF_CC_BACKEND := nrf_cc310_mbedcrypto
  ARCH_DIR   := cortex-m4
  FLOAT_DIR  := soft-float
  RESC := run_sign.resc

else ifeq ($(TARGET),nrf5340dk)
  PLATFORM := platforms/nrf5340dk
  STARTUP := $(PLATFORM)/startup.c
  LDS  := $(PLATFORM)/linker.ld
  CFLAGS := -mcpu=cortex-m33 -mthumb -mfloat-abi=soft -mfpu=fpv5-sp-d16 -O2 \
            -ffreestanding -Wall -Wextra -Wl,--gc-sections  \
            -I$(NRFXLIB_DIR)/crypto/nrf_oberon/include
  LDFLAGS := -T $(LDS) -Wl,-Map,sign_nrf5340dk.map -specs=nano.specs -nostartfiles
  ARCH_DIR   := cortex-m33+nodsp
  FLOAT_DIR  := soft-float
  ELF := sign_nrf5340dk.elf
  # NRF_CC_BACKEND := nrf_cc312_mbedcrypto
  RESC := ./ci/renode/run_sign_nrf5340dk.resc

endif

#SHA256 := $(PLATFORM)/sha256.c
# compute SHA-256 without hardware acceleration (temporary)
SHA256 := platforms/sha256.c
#vpath sha256.c $(PLATFORM) 
vpath sha256.c platforms

# Only use KAT rng.c when make KAT_RNG=1
ifeq ($(KAT_RNG),1)
  RNG_SRC := kat/rng.c kat/kat_rng.c kat/aes256.c
  CFLAGS  += -DKAT_RNG
endif

CFLAGS += -Ithird_party/mbedtls/include

LDFLAGS += -Wl,--start-group -lc -lgcc -Wl,--end-group -Wl,-u,memcpy -Wl,-u,__aeabi_memcpy

NM ?= $(shell $(CC) -print-prog-name=nm)

ifneq ($(NRF_CC_BACKEND),)
CFLAGS += -I$(NRFXLIB_DIR)/crypto/$(NRF_CC_BACKEND)/include
endif

SRCS := $(STARTUP) $(RNG_SRC) unsafe/psa_crypto.c main.c \
        keygen.c $(SHA256) uart_min.c slh_dsa_sign.c \
        base_2b.c addr_compressed.c addr.c \
        xmss_sign.c \
        common.c fors_sk_gen.c thf.c fors_sign.c chain.c

RENODE_IMG = renode_pinned:cached

WORKDIR     ?= $(shell pwd)
RESC        ?= run_sign.resc

RNG_OBJS := $(RNG_SRC:.c=.o)

psa_crypto.o: unsafe/psa_crypto.c
	$(CC) $(CFLAGS) -c $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

ifneq ($(filter clean,$(MAKECMDGOALS)),)
  # do nothing
else
  $(info NRFXLIB_DIR = $(NRFXLIB_DIR))
  $(info NRF_CC_BACKEND = $(NRF_CC_BACKEND))
  $(info RNG_SRC = $(RNG_SRC))
  $(info RNG_OBJS = $(RNG_OBJS))

endif

OBERON_LIB := $(NRFXLIB_DIR)/crypto/nrf_oberon/lib/$(strip $(ARCH_DIR))/$(strip $(FLOAT_DIR))/liboberon_3.0.17.a

all: sign.elf

sign.elf:  $(LDS) $(OBJS) $(RNG_OBJS)
	@echo "==> start building with $(CC), output should be $(ELF)"
	$(CC) $(CFLAGS) $(SRCS) -v $(OBERON_LIB) $(LDFLAGS) -o $(ELF)
# check memcpy has real implementation
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
