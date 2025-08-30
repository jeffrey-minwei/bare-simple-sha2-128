CC := arm-none-eabi-gcc
CFLAGS := -mcpu=cortex-m4 -mthumb -O2 -ffreestanding -nostdlib -Wall -Wextra -Wl,--gc-sections
ELF := sign.elf
SRCS := startup.c main.c
LDS  := linker.ld

# 用 digest 來完全鎖定版本
RENODE_IMG = antmicro/renode@sha256:1a4879e047b22827205f4fb1d1e5474d5fdce17eb69f22726ab1afed479f5e22

WORKDIR     ?= $(shell pwd)
RESC        ?= run_sign.resc

.PHONY: all clean run ci-run
all: $(ELF)
$(ELF): $(SRCS) $(LDS)
	$(CC) $(CFLAGS) -T $(LDS) $(SRCS) -o $@

clean:
	rm -f $(ELF)

# 本機（有裝 renode）
run: $(ELF) $(RESC)
	renode -e 'include @$(RESC); sleep 2; q'

# CI：用官方 renode 容器；CI 只呼叫這個 target
ci-run: $(ELF) $(RESC)
	docker run --rm -v "$(WORKDIR):/w" $(RENODE_IMG) \
	  sh -lc 'cd /w && renode --console --disable-xwt -e "set ansi false; include @$(RESC); sleep 2; q"' | sed 's/\x1B\[[0-9;]*[A-Za-z]//g'
