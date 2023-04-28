#!/bin/bash

for creds_file in credentials-openai.txt credentials-discord.txt; do
	if [ -f $creds_file ]; then
		source $creds_file;
		if [ $? -ne 0 ]; then
			echo "Error reading credentials file ${creds_file}'; exiting."
			exit 1 
		fi
	else
		echo "Missing required credentials file ${creds_file}'; exiting."
		exit 1 
	fi
done

python3 george.py
