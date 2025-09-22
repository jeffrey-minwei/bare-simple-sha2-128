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

OBJS := addr_compressed.o common.o base_2b.o keygen.o sha256.o slh_dsa_sign.o fors_sign.o fors_sk_gen.o

CC := arm-none-eabi-gcc

ifeq ($(TARGET),x86)
  CC := gcc
  CFLAGS := -O3 -std=c11 -Wall -Wextra -Wpedantic -ffunction-sections -fdata-sections -mrdrnd -Wl,--gc-sections
  LDFLAGS := -Wl,-Map,x86_sign.map
  STARTUP :=                         # like platform/x86/startup.c
  LDS  :=                            # like platform/x86/linker.ld
  RAND_SRC := platforms/x86/rdrand.c
  OBJCOPY := objcopy
  SIZE := size
  ELF := sign_x86.elf

else ifeq ($(TARGET),nrf52840)
  STARTUP := platforms/nrf52840/startup.c
  LDS  := platforms/nrf52840/linker.ld
  RAND_SRC := platforms/nrf52840/rdrand.c
  CFLAGS := -mcpu=cortex-m4 -mthumb -O2 -ffreestanding -Wall -Wextra -Wl,--gc-sections -specs=nano.specs -nostartfiles
  LDFLAGS := -T $(LDS) -Wl,-Map,sign_nrf52840.map -Wl,--whole-archive $(NRFXLIB_DIR)/crypto/nrf_cc310_bl/lib/cortex-m4/soft-float/libnrf_cc310_bl_0.9.12.a -Wl,--no-whole-archive
  ELF := sign_nrf52840.elf
  NRF_CC_BACKEND := nrf_cc310_mbedcrypto

else ifeq ($(TARGET),nrf5340)
  STARTUP := platforms/nrf5340dk/startup.c
  LDS  := platforms/nrf5340dk/linker.ld
  RAND_SRC := platforms/nrf5340dk/rdrand.c
  CFLAGS := -mcpu=cortex-m33 -mthumb -O2 -ffreestanding -Wall -Wextra -Wl,--gc-sections -specs=nano.specs -nostartfiles
  LDFLAGS := -T $(LDS) -Wl,-Map,sign_nrf5340.map
  ELF := sign_nrf5340dk.elf
  NRF_CC_BACKEND := nrf_cc312_mbedcrypto

endif

LDFLAGS += -Wl,--start-group -lc -lgcc -Wl,--end-group -Wl,-u,memcpy -Wl,-u,__aeabi_memcpy

NM ?= $(shell $(CC) -print-prog-name=nm)

SRCS := $(STARTUP) $(RAND_SRC) main.c keygen.c sha256.c uart_min.c slh_dsa_sign.c base_2b.c addr_compressed.c common.c fors_sk_gen.c fors_sign.c

# 用 digest 來完全鎖定版本
RENODE_IMG = antmicro/renode@sha256:1a4879e047b22827205f4fb1d1e5474d5fdce17eb69f22726ab1afed479f5e22

WORKDIR     ?= $(shell pwd)
RESC        ?= run_sign.resc

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

all: sign.elf

sign.elf:  $(LDS) $(OBJS)
	@echo "==> start building with $(CC), output should be $(ELF)"
	$(CC) $(CFLAGS) $(SRCS) -v $(LDFLAGS) -o $(ELF)
# check memcpy has real implementation
	$(NM) $(ELF) | grep -E 'memcpy|__aeabi_memcpy'

clean:
	rm -f *.o sign_*.elf sign.elf
	rm -f $(ELF)

# 本機（有裝 renode）
run: $(ELF) $(RESC)
	renode -e 'include @$(RESC); sleep 2; q'

# CI：用官方 renode 容器；CI 只呼叫這個 target
ci-run-nrf52840: $(ELF) $(RESC)
	docker run --rm -v "$(WORKDIR):/w" $(RENODE_IMG) \
	  sh -lc 'cd /w && renode --console --disable-xwt -e "set ansi false; include @$(RESC); sleep 2; q"' | sed 's/\x1B\[[0-9;]*[A-Za-z]//g' 
