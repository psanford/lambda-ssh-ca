override FUNCTION_NAME=ssh-ca
override CONF_BUCKET=lambda-config-sanford-io
override LAMBDA_BINARY_BUCKET=lambda-src-sanford
override GOSRC=$(wildcard *.go) $(wildcard **/*.go) $(wildcard templates/*)

include $(HOME)/projects/lambdamake/Makefile.arm
