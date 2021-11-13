# PSI Admin Panel
> **Disclaimer:** I DO NOT condone cheating in any form.  This article will not demonstrate how to bypass the secure browser and there are still safeguards in place and logs submitted to detect cheating even with the panel enabled.  This article only exists for **educational** purposes. 

[PSI Secure Browser](https://www.psionline.com/education/online-proctoring) is an online monitoring software that aims to prevent cheating.  RPINow records the test session which is then manually reviewed later.  I decided to take a look at the software to discover whether it really is as secure as it claims.

- MD5: `ce5b51ec4e0d55743d7793a35f48699e`
- SHA256: `775d3218f23e3b55176bf2dae0c4b9c12a86da6fb5bc9e487d2269c4f27bc5f9`

## Initial Analysis
PSI Secure Browser was developed using the Electron framework.  In brief, Electron enables developers to efficiently package web apps into native desktop apps.  The application is distributed through a bundle packaged with Chromium browser.  Electron apps contain a compressed archive containing the application's package.  We can unpack the `app.asar` archive with the `asar` package available from [NPM](https://www.npmjs.com/package/asar). (*Due to this mechanism we can later repack our modified code to instrument the application*)

`asar extract app.asar extracted-app`

The unpacked contents reveal a npm package bundled with javascript code.  Typically, developers will minify or obfuscate the code to make reverse engineering more difficult.  Fortunately, the available code is untouched so analysis will be simple.

I looked around and played with the application until I discovered a weird line in the code.
```js
const defaultValues = {
    // ...
    adminPanel: {
        security: {
            keystrokeCombination: 'Eecew3lr-7QHE2ZXWQuVf3U5zEOn7A==',
            adminPanelPassCode: 'M70k3JolNxSphfTCcIryWNAMdYGAPE-EPEhkjC_s',
        },
    },
    // ...
};
```

Well, okay.  Now we definitely know there is a hidden admin panel embedded within the application but the credentials are encrypted.  
But how do we extract the credentials?

Turns out that during browser configuration it fetches a base64 encoded ZIP file from `https://[REDACTED]/sb/data/VTXL4` and checks access to VTXL4 under the `.cfg` directory. 

```sh
curl -XPOST https://[REDACTED]/sb/data/VTXL4 | base64 -d > vtxl4.zip
unzip -l vtxl4.zip

Archive:  vtxl4.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2021-09-15 06:33   edX/
        0  2021-09-15 06:33   edX/Content/
      195  2021-09-15 06:33   edX/Content/above-tabs.html
     7983  2021-09-15 06:33   edX/conf.yaml
       65  2021-09-15 06:33   edX/layout.yaml
        0  2021-09-15 06:33   edX/locales/
        0  2021-09-15 06:33   edX/locales/en/
     1264  2021-09-15 06:33   edX/locales/en/orgtext.json
      812  2021-09-15 06:33   edX/secrets.json
---------                     -------
    10319                     9 files
```

The `secrets.json` file contains encrypted secrets and other information used during browser initialization. 
To decrypt the encrypted passcodes from `secrets.json` it relies on a custom binary `psi-bastion` located under `resources/.apps`.

```js
const cryptJSON = (action, keys, body, doSynchronously = false) => {
    const parameters = {
        control: {
            keys,
        },
        body,
    };
    const crPath = (0, utils_1.getExecutablePath)('psi-bastion');
    const bastionLogFile = `${sb_1.SBg.SB.logDirectory}/bastionCRLog_${sb_1.SBg.SB.datestring}`;
    const crArgs = ['-l', bastionLogFile, 'crypt', 'decrypt'];
    try {
        const data = (0, child_process_1.execFileSync)(crPath, crArgs, {
            input: `${JSON.stringify(parameters)}\n`,
        });
        try {
            const resp = JSON.parse(data.toString());
            // ...
        }
    }
};
```

## Analyzing the binary
`psi-bastion` is a x86/64 binary written in Go.  Luckily for us, the binary contains DWARF debug information so analyzing the binary should not be too difficult.  The binary supports various command-line arguments used by the secure browser to perform operations.

```powershell
Start-Process -NoNewWindow -FilePath .\psi-bastion.exe
Bastion implements security as a command line utility.

Usage:
  psi-bastion [command]

Available Commands:
  clipboard   handles clipboard commands
  crypt       encrypt or decrypt.
  help        Help about any command
  mon         Getting information about attached monitors.
  ps          ps (process status) lists and kills system processes.
  vmdetect    vmdetect detects whether you're in a virtual machine
  webserver   webserver deals with starting and stopping the web server.

Flags:
      --config string    config file (default is $HOME/.psi-bastion.yaml)
  -h, --help             help for psi-bastion
  -l, --logfile string   name of log file
  -v, --verbose          Use this flag to add debug information to the log file.

Use "psi-bastion [command] --help" for more information about a command.
subcommand is required
```

Using the binary directly, we are able to decrypt the information stored in `secrets.json`.  

```sh
echo '{"control": {"keys": ["adminPanel"]}, "body": {"adminPanel": {"security": {"keystrokeCombination": "Eecew3lr-7QHE2ZXWQuVf3U5zEOn7A==", "adminPanelPassCode": "M70k3JolNxSphfTCcIryWNAMdYGAPE-EPEhkjC_s"}}}}' | ./.apps/windows/x64/psi-bastion.exe crypt decrypt
{"adminPanel":{"security":{"keystrokeCombination":"...","adminPanelPassCode":"..."}}}
```

Internally, the binary relies on a 128/256-bit AES cipher to encrypt/decrypt information with a hardcoded symmetric key.

![image](https://user-images.githubusercontent.com/51222153/141659084-19a2ec1f-8cd9-4c6a-bc25-d702189823ef.png)

## Results
Entering the admin passcode into the admin panel will reveal several tools that allow for controlling the environment.  There are options to open the dev tools panel, list/kill processes and disable security. 

![image](https://user-images.githubusercontent.com/51222153/141659125-728b4245-0d46-4bec-8ed7-54794fd29b42.png)

