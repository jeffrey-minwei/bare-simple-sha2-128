.DEFAULT_GOAL := all
.PHONY: all kat

# ===== nRF nrfxlib (CC31x) autodetect: headers + libs =====
NRFXLIB_DIR ?= $(abspath third_party/nrfxlib)

# kat clean help ci-run 以外一律要指定 TARGET
ifeq (,$(filter kat clean help ci-run%,$(MAKECMDGOALS)))

ifeq ($(strip $(TARGET)),)
$(error TARGET is required, ex. make TARGET=nrf52840)
endif

# nrfxlib/crypto is required
ifeq ("$(wildcard $(NRFXLIB_DIR)/crypto)","")
$(error FATAL: nrfxlib not found at $(NRFXLIB_DIR))
endif

endif

OBJS := addr_compressed.o thf.o common.o addr.o \
        base_2b.o sha256.o \
        slh_dsa_sign.o fors_sign.o 

OBJS += xmss_sign.o wots_plus.o \
        mgf1_sha256_len30.o psa_crypto.o hmac_sha256.o

CC := arm-none-eabi-gcc

ifeq ($(TARGET),nrf52840)
  PLATFORM := platforms/nrf52840
  STARTUP := $(PLATFORM)/startup.c
  CFLAGS := -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -mfpu=fpv4-sp-d16 -O2 \
            -ffreestanding -Wall -Wextra 
            #-I$(NRFXLIB_DIR)/crypto/nrf_cc310_mbedcrypto/include 
  LDFLAGS := -T $(PLATFORM)/linker.ld -Wl,-Map,sign_nrf52840.map \
             -specs=nano.specs -nostartfiles
  ELF := sign_nrf52840.elf
  # NRF_CC_BACKEND := nrf_cc310_mbedcrypto
  ARCH_DIR   := cortex-m4
  RESC := run_sign.resc

else ifeq ($(TARGET),nrf5340dk)
  PLATFORM := platforms/nrf5340dk
  STARTUP := $(PLATFORM)/startup.c
  CFLAGS := -mcpu=cortex-m33 -mthumb -mfloat-abi=soft -mfpu=fpv5-sp-d16 -O2 \
            -ffreestanding -Wall -Wextra 
  LDFLAGS := -T $(PLATFORM)/linker.ld -Wl,-Map,sign_nrf5340dk.map \
             -specs=nano.specs -nostartfiles
  ARCH_DIR   := cortex-m33+nodsp
  ELF := sign_nrf5340dk.elf
  # NRF_CC_BACKEND := nrf_cc312_mbedcrypto
  RESC := ./ci/renode/run_sign_nrf5340dk.resc

endif

FLOAT_DIR  := soft-float

#SHA256 := $(PLATFORM)/sha256.c
# compute SHA-256 without hardware acceleration (temporary)
SHA256 := platforms/sha256.c
#vpath sha256.c $(PLATFORM) 
vpath sha256.c platforms

RNG_SRC := kat/rng.c kat/aes256.c

CFLAGS += -Ithird_party/mbedtls/include

LDFLAGS += -Wl,--start-group -lc -lgcc -Wl,--end-group -Wl,-u,memcpy -Wl,-u,__aeabi_memcpy

NM ?= $(shell $(CC) -print-prog-name=nm)

ifneq ($(NRF_CC_BACKEND),)
CFLAGS += -I$(NRFXLIB_DIR)/crypto/$(NRF_CC_BACKEND)/include
endif

SRCS := $(STARTUP) $(RNG_SRC) unsafe/psa_crypto.c \
        $(SHA256) unsafe/hmac_sha256.c \
        unsafe/mgf1_sha256_len30.c \
        uart_min.c slh_dsa_sign.c \
        base_2b.c addr_compressed.c addr.c \
        xmss_sign.c wots_plus.c \
        common.c thf.c fors_sign.c

RENODE_IMG = renode_pinned:cached

WORKDIR     ?= $(shell pwd)
RESC        ?= run_sign.resc

RNG_OBJS := $(RNG_SRC:.c=.o)

mgf1_sha256_len30.o: unsafe/mgf1_sha256_len30.c
	$(CC) $(CFLAGS) -c $^ -o $@

hmac_sha256.o: unsafe/hmac_sha256.c
	$(CC) $(CFLAGS) -c $^ -o $@

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
  $(info TARGET = $(TARGET))

endif

all: sign.elf

sign.elf:  $(PLATFORM)/linker.ld $(OBJS) $(RNG_OBJS)
	@echo "==> start building with $(CC), output should be $(ELF)"
	$(CC) $(CFLAGS) main.c $(SRCS) -v $(LDFLAGS) -o $(ELF)
	$(NM) $(ELF) | grep -E 'memcpy|__aeabi_memcpy'

clean:
	rm -f *.o sign_*.elf sign.elf
	rm -f $(ELF)

run: $(ELF) $(RESC)
	renode -e 'include @$(RESC); sleep 2; q'

RENODE  ?= ./renode_portable/renode

strip_ansi = sed 's/\x1B\[[0-9;]*[A-Za-z]//g'

ci-run-nrf52840: $(ELF) $(RESC)
	$(RENODE) --console --disable-xwt \
		-e "set ansi false; include @$(RESC); sleep 2; q" \
		| $(strip_ansi)

ci-run-nrf5340dk: $(ELF) $(RESC)
	$(RENODE) --console --disable-xwt -e 'help; q' | grep -i UART | sed 's/\x1B\[[0-9;]*[A-Za-z]//g'
	$(RENODE) --console --disable-xwt \
		-e "set ansi false; include @$(RESC); sleep 2; q" \
		| $(strip_ansi)


# 主機編譯器與 OpenSSL
HOSTCC      ?= gcc
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
  OPENSSL_LIBS := -lcrypto
endif

HOSTCFLAGS  := -O2 -std=c11 -Wall -Wextra -DNDEBUG -DUSE_NIST_KAT_RNG $(OPENSSL_CFLAGS)
HOSTLDFLAGS := $(OPENSSL_LIBS)

# 目錄與檔案（自行依專案調整）
KAT_DIR     ?= kat
KAT_SRCS    := $(KAT_DIR)/PQCgenKAT_sign.c 
KAT_INCS    := -I. -I$(KAT_DIR) -Iref -Ithird_party/mbedtls/include

KAT_BUILD   ?= kat
KAT_BIN     := $(KAT_BUILD)/PQCgenKAT_sign

kat:
	@mkdir -p $(KAT_BUILD)
	$(HOSTCC) $(HOSTCFLAGS) $(KAT_INCS) $(KAT_SRCS) -DX86 $(SRCS) -o $(KAT_BIN) $(HOSTLDFLAGS)
	@echo "[KAT] running in $(KAT_BUILD)"
	@cd $(KAT_BUILD) && ./PQCgenKAT_sign
	@ls -l $(KAT_BUILD)/PQCsignKAT_*.req $(KAT_BUILD)/PQCsignKAT_*.rsp 2>/dev/null || true