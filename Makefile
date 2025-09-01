CC := arm-none-eabi-gcc
CFLAGS := -mcpu=cortex-m4 -mthumb -O2 -ffreestanding -Wall -Wextra -Wl,--gc-sections -specs=nano.specs -specs=nosys.specs 

ELF := sign.elf
SRCS := startup.c main.c keygen.c sha256.c uart_min.c slh_dsa_sign.c base_2b.c
LDS  := linker.ld
TEST_SRCS := tests/test_keygen.c startup.c keygen.c

# 用 digest 來完全鎖定版本
RENODE_IMG = antmicro/renode@sha256:1a4879e047b22827205f4fb1d1e5474d5fdce17eb69f22726ab1afed479f5e22

WORKDIR     ?= $(shell pwd)
RESC        ?= run_sign.resc

.PHONY: all clean run ci-run

sign.elf: $(OBJS) $(LDS)
	$(CC) $(CFLAGS) -T $(LDS) $(OBJS) \
	-Wl,--gc-sections -Wl,-Map,sign.map \
	-specs=nano.specs -specs=nosys.specs \
	-lc -lnosys -lgcc -o $@

keygen.o: keygen.c
	$(CC) $(CFLAGS) -c $^ -o $@

sha256.o: sha256.c
	$(CC) $(CFLAGS) -c $^ -o $@

base_2b.o: base_2b.c
	$(CC) $(CFLAGS) -c $^ -o $@

slh_dsa_sign.o: slh_dsa_sign.c
	$(CC) $(CFLAGS) -c $^ -o $@

all: $(ELF) 
$(ELF): $(SRCS) $(LDS) base_2b.o keygen.o sha256.o slh_dsa_sign.o
	$(CC) $(CFLAGS) -T $(LDS) $(SRCS) -Wl,-Map,sign.map -v -Wl,--start-group -lc -lnosys -lgcc -Wl,--end-group -o $@

clean:
	rm -f $(ELF)

# 本機（有裝 renode）
run: $(ELF) $(RESC)
	renode -e 'include @$(RESC); sleep 2; q'

# CI：用官方 renode 容器；CI 只呼叫這個 target
ci-run: $(ELF) $(RESC)
	docker run --rm -v "$(WORKDIR):/w" $(RENODE_IMG) \
	  sh -lc 'cd /w && renode --console --disable-xwt -e "set ansi false; include @$(RESC); sleep 2; q"' | sed 's/\x1B\[[0-9;]*[A-Za-z]//g' 