# Depends: sdcc, binpac8x

# ADJUST TO YOUR SYSTEM!
BINPACK8X = /data/main/dpr/rr/wpru/ti84plus/binpac8x/binpac8x.py

PROGRAM = trtotp

compile: tios_crt0.rel
	sdcc --no-std-crt0 --code-loc 40347 --data-loc 0 --std-sdcc99 -mz80 \
		--opt-code-size \
		--reserve-regs-iy -o $(PROGRAM).ihx tios_crt0.rel $(PROGRAM).c
	objcopy -I ihex -O binary $(PROGRAM).ihx $(PROGRAM).bin
	$(BINPACK8X) $(PROGRAM).bin

tios_crt0.rel: tios_crt0.s
	sdasz80 -p -g -o tios_crt0.rel tios_crt0.s

clean:
	-rm tios_crt0.rel $(PROGRAM).ihx $(PROGRAM).bin $(PROGRAM).lst \
		$(PROGRAM).map $(PROGRAM).noi $(PROGRAM).lk $(PROGRAM).asm \
		$(PROGRAM).rel $(PROGRAM).sym 2> /dev/null

dist-clean: clean
	-rm $(PROGRAM).8xp
