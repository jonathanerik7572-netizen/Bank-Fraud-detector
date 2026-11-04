#!/usr/bin/env bash
cd "$(dirname "$0")"
gcc main.c -o bank_fraud_detector -O2 -Wall
./bank_fraud_detector
