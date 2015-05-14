all:
	@echo "make doc   :  Make Doxygen documentation"

doc:
	doxygen

clean:
	@rm -rf doc

.PHONY: doc
