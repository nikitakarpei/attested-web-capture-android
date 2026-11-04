.PHONY: verification-metadata

# Writes gradle/verification-metadata.xml again after a dependency changes (see the script); review the diff.
verification-metadata:
	tools/update-verification-metadata.sh
