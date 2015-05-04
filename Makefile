all: libswitchapi.a
	@echo "public incs: $(libswitchapi.a_PUBLIC_INCS)"
	@echo "target path: $(libswitchapi.a_TARGET)"

include libswitchapi.mk
