# Bank Fraud Detector — Render-ready C web application

This is the Render deployment package for the Bank Fraud Detector with two separate workspaces:

- **Transaction Generator:** `/generator` — enter fictional sender/beneficiary names, account numbers, bank, amount, country, transaction type, channel and risk context, then submit to the server queue.
- **Fraud Analysis Centre:** `/analyzer` — independently view queued transactions and process them one-by-one or automatically.

The C server handles the queue and rule-based risk analysis. This is a classroom simulation, not a real banking integration or trained ML model. The in-memory queue clears when the server restarts and is not persistent across restarts or multiple server instances. Use fictional data only.

## Deploy to Render (recommended: Docker)

### 1. Create a GitHub repository
1. Extract this ZIP.
2. Create a new empty GitHub repository.
3. Upload **the contents of this folder** to the repository root, not the enclosing folder. At repository root you must see `Dockerfile`, `render.yaml`, `main.c`, and the `public` folder.
4. Commit the files to the `main` branch.

Expected repository layout:

```text
repository-root/
├── Dockerfile
├── render.yaml
├── .dockerignore
├── main.c
└── public/
    ├── generator.html
    ├── analyzer.html
    └── index.html
```

### 2. Create the Render service
1. Sign in to Render and choose **New + → Blueprint** (or **New + → Web Service** and connect the repository).
2. If using Blueprint, select the repository containing `render.yaml` and apply the Blueprint.
3. If creating a Web Service manually, choose **Docker** as the runtime/environment.
4. Set **Root Directory** to blank (the repository root), **Dockerfile Path** to `./Dockerfile`, and **Docker Context Directory** to `.`.
5. Deploy. The Dockerfile compiles the C server for Linux and starts it using Render's `PORT` environment variable.

Do not enter the Windows GCC command as the Render build command. Do not upload `run_windows.bat` as a start command. Render uses the Dockerfile.

### 3. Open the two workspaces
After deployment completes, open the Render URL:

- Transaction Generator: `https://YOUR-SERVICE.onrender.com/generator`
- Fraud Analysis Centre: `https://YOUR-SERVICE.onrender.com/analyzer`
- Health check: `https://YOUR-SERVICE.onrender.com/api/health`

Replace `YOUR-SERVICE` with the actual Render service hostname. Keep the same deployed service running; both pages communicate with the same C server queue.

## Run locally on Windows
1. Install MSYS2 UCRT64 GCC.
2. Double-click `run_windows.bat` or compile manually:

```bash
gcc main.c -o bank_fraud_detector.exe -lws2_32 -O2 -Wall
./bank_fraud_detector.exe
```

3. Open `http://localhost:8080/generator` and `http://localhost:8080/analyzer`.

## How the demo works
1. Enter made-up sender and beneficiary details in the Generator and submit a transaction.
2. The C server places it in an in-memory queue.
3. In the separate Analysis Centre, click **Process Next Transaction** or **Start Auto Analysis**.
4. The C engine calculates a risk score and displays the indicators and recommended action.

## Important limitations
- Synthetic classroom demo only. No real money moves and no bank/payment network is connected.
- The risk engine is rule-based, not a trained machine-learning model.
- Queue data is held in RAM; it clears on restart and is unsuitable for production or multiple instances.
- Use only fictional account details. Do not collect or enter real personal or financial information.
- A real production system would need authentication, authorization, HTTPS, a database/queue service, audit logs, secure handling of sensitive data, regulatory review and a validated model.
