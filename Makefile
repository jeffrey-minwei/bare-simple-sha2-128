.DEFAULT_GOAL := all
.PHONY: all

# clean help ci-run 以外一律要指定 TARGET
ifeq (,$(filter clean help ci-run%,$(MAKECMDGOALS)))
ifeq ($(strip $(TARGET)),)
$(error TARGET is required, ex. make TARGET=nrf52840)
endif
endif

OBJS := common.o base_2b.o keygen.o sha256.o slh_dsa_sign.o fors_sign.o fors_sk_gen.o


ifeq ($(TARGET),x86)
  CC := gcc
  CFLAGS := -O3 -std=c11 -Wall -Wextra -Wpedantic -ffunction-sections -fdata-sections -mrdrnd
  LDFLAGS := -Wl,--gc-sections -Wl,-Map,x86_sign.map
  STARTUP :=                         # like platform/x86/startup.c
  LDS  :=                            # like platform/x86/linker.ld
  RAND_SRC := platforms/x86/rdrand.c
  OBJCOPY := objcopy
  SIZE := size
  ELF := sign_x86.elf

else ifeq ($(TARGET),nrf52840)
  CC := arm-none-eabi-gcc
  STARTUP := platforms/nrf52840/startup.c
  LDS  := platforms/nrf52840/linker.ld
  RAND_SRC := platforms/nrf52840/rdrand.c
  CFLAGS := -mcpu=cortex-m4 -mthumb -O2 -ffreestanding -Wall -Wextra  
  LDFLAGS := -Wl,--gc-sections -specs=nano.specs -specs=nosys.specs -nostartfiles -lc -lnosys -lgcc -T $(LDS) -Wl,-Map,sign_nrf52840.map
  ELF := sign_nrf52840.elf

else ifeq ($(TARGET),nrf5340dk)
  CC := arm-none-eabi-gcc
  STARTUP := platforms/nrf5340dk/startup.c
  LDS  := platforms/nrf5340dk/linker.ld
  RAND_SRC := platforms/nrf5340dk/rdrand.c
  CFLAGS := -mcpu=cortex-m33 -mthumb -O2 -ffreestanding -Wall -Wextra  
  LDFLAGS := -Wl,--gc-sections -specs=nano.specs -specs=nosys.specs -nostartfiles -lc -lnosys -lgcc -T $(LDS) -Wl,-Map,sign_nrf5340dk.map
  ELF := sign_nrf5340dk.elf

endif

SRCS := $(STARTUP) $(RAND_SRC) main.c keygen.c sha256.c uart_min.c slh_dsa_sign.c base_2b.c common.c fors_sk_gen.c fors_sign.c

# 用 digest 來完全鎖定版本
RENODE_IMG = antmicro/renode@sha256:1a4879e047b22827205f4fb1d1e5474d5fdce17eb69f22726ab1afed479f5e22

WORKDIR     ?= $(shell pwd)
RESC        ?= run_sign.resc

common.o: common.c
	$(CC) $(CFLAGS) -c $^ -o $@

keygen.o: keygen.c
	$(CC) $(CFLAGS) -c $^ -o $@

sha256.o: sha256.c
	$(CC) $(CFLAGS) -c $^ -o $@

base_2b.o: base_2b.c
	$(CC) $(CFLAGS) -c $^ -o $@

fors_sk_gen.o: fors_sk_gen.c
	$(CC) $(CFLAGS) -c $^ -o $@

fors_sign.o: fors_sign.c
	$(CC) $(CFLAGS) -c $^ -o $@

slh_dsa_sign.o: slh_dsa_sign.c
	$(CC) $(CFLAGS) -c $^ -o $@

all: sign.elf

sign.elf:  $(LDS) $(OBJS)
	@echo "==> start building with $(CC), output should be $(ELF)"
	$(CC) $(CFLAGS) $(SRCS) -v -Wl,--start-group -Wl,--end-group $(LDFLAGS) -o $(ELF)

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