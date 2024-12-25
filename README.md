


## Introduction:

This project has been developed to query IP address-based vulnerabilities in the dataset available in the Tenable Security Center. The results are saved to an Excel file.

## Prepare .env file first:

Create a file named .env. This file contains access information related to the Security Center environment you will be working on. To activate the definitions in the file, you must run the source .env command after each change.

### Sample ".env" file content: 
```
export ACCESS_KEY=d9ee3af256b1409a8163f05256axxxxx
export SECRET_KEY=35dc488afb474c88afd07197a2xxxxxx
export SC_URL=https://localhost:8443/

```


## Create Python Environment:

Run the following commands to define a project-specific virtual Python environment, install the dependencies, and activate the environment.

```bash
cd <project-folder>
python3 -m venv .venv
source .env
source .venv/bin/activate
pip3 install -r requirements.txt
./get-vuln.py -t <target-ip>
```

## Support
This project is provided as open-source for your use. You cannot receive official support from Tenable regarding this project. For any questions or bug reports, you can open an issue on GitHub.

