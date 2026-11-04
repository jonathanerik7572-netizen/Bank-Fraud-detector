FROM gcc:14-bookworm
WORKDIR /app
COPY main.c ./main.c
COPY public ./public
RUN gcc -O2 -Wall -Wextra -o bank_fraud_detector main.c
ENV PORT=10000
EXPOSE 10000
CMD ["./bank_fraud_detector"]
