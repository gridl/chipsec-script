# chipsec-script
### Usage
* Runs in an empty directory:

	```
	sudo python chipsec_script.py > result.log
	```
### As a result of the script working 
* The directory contains the following files:
	
	![image](https://github.com/yeggor/chipsec-script/blob/master/images/directory.PNG)
	- Outputs of modules that were started (.txt files)
	- Output of the chipsec_script.py (result.log)
	- Additional files (for example, the dump of UEFI firmware)
* The result.log contains information about the security of the UEFI firmware:

	![image](https://github.com/yeggor/chipsec-script/blob/master/images/result.PNG)	

