# xdp-tools-test
This is a xdp-tools test suite using python unittest

# How to run

## Step 1
check `config.toml` config file. This file is the only configuration file you need to deal with. PLEASE make sure you're using the right exec file. 
```
exec_file = "complied" # 'complied' or 'system'. complied will test upstream xdp-tools repo's complied exec file, sytem will test the xdp-tools by using system's pkg
```

## Step 2 
`./setup.sh` and resolve any error

## Step 3
`sudo python3 run_test.py`

You can open another terminal and `tail -f output.log`

## Step 4
After all test done, you can use `./cleanup` to clean all the temp file.