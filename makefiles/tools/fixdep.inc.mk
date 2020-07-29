# Define tools to use
FIXDEP_DIR ?= $(RIOTTOOLS)/fixdep
FIXDEP ?= $(FIXDEP_DIR)/fixdep

$(FIXDEP):
	@echo "[INFO] fixdep not found - building it"
	@$(MAKE) -C $(FIXDEP_DIR)
