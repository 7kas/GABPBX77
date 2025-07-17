sed -i 's/ASTERISK/GABPBX/g' $1
sed -i 's/Asterisk/GABpbx/g' $1
sed -i 's/asterisk/gabpbx/g' $1

j=`echo $1 | sed 's/asterisk/gabpbx/g'`; mv "$1" "$j"; 
