<?php
class convert {
	
	public static function stringToHex ($s) {
		// $r = "0x";
		$r = "";
		$hexes = array ("0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F");		      
        for ($i=0; $i<strlen($s); $i++) {
            $r .= ($hexes [(ord($s[$i]) >> 4)] . $hexes [(ord($s[$i]) & 0xf)]);
        }
		return $r;
	}
	
	public static function hexToString ($h) {
		$r = "";
		for ($i= (substr($h, 0, 2)=="0x")?2:0; $i<strlen($h); $i+=2) {$r .= chr (base_convert (substr ($h, $i, 2), 16, 10));}
		return $r;
	}
	
	public static function hexToBin($hex){
		$bin="";
		for ($i=0; $i<strlen($hex); $i++){
			if ($hex[$i]=="0") $bin .= "0000" ;
			if ($hex[$i]=="1") $bin .= "0001" ;
			if ($hex[$i]=="2") $bin .= "0010" ;
			if ($hex[$i]=="3") $bin .= "0011" ;
			if ($hex[$i]=="4") $bin .= "0100" ;
			if ($hex[$i]=="5") $bin .= "0101" ;
			if ($hex[$i]=="6") $bin .= "0110" ;
			if ($hex[$i]=="7") $bin .= "0111" ;
			if ($hex[$i]=="8") $bin .= "1000" ;
			if ($hex[$i]=="9") $bin .= "1001" ;
			if ($hex[$i]=="A") $bin .= "1010" ;
			if ($hex[$i]=="B") $bin .= "1011" ;
			if ($hex[$i]=="C") $bin .= "1100" ;
			if ($hex[$i]=="D") $bin .= "1101" ;
			if ($hex[$i]=="E") $bin .= "1110" ;
			if ($hex[$i]=="F") $bin .= "1111" ;
		}
		return $bin;
	}

	public static function dec16ToBin($dec){
		if ($dec==0) $bin = "0000" ;
		if ($dec==1) $bin = "0001" ;
		if ($dec==2) $bin = "0010" ;
		if ($dec==3) $bin = "0011" ;
		if ($dec==4) $bin = "0100" ;
		if ($dec==5) $bin = "0101" ;
		if ($dec==6) $bin = "0110" ;
		if ($dec==7) $bin = "0111" ;
		if ($dec==8) $bin = "1000" ;
		if ($dec==9) $bin = "1001" ;
		if ($dec==10) $bin = "1010" ;
		if ($dec==11) $bin = "1011" ;
		if ($dec==12) $bin = "1100" ;
		if ($dec==13) $bin = "1101" ;
		if ($dec==14) $bin = "1110" ;
		if ($dec==15) $bin = "1111" ;
		return $bin;
	}

	public static function binToHex($bin){
		$hex="";
		for ($i=0; $i<strlen($bin); $i=$i+4){
			$bin4 = $bin[$i] . $bin[$i+1] . $bin[$i+2] . $bin[$i+3];
			if ($bin4=="0000") $hex .=  "0";
			if ($bin4=="0001") $hex .=  "1";
			if ($bin4=="0010") $hex .=  "2";
			if ($bin4=="0011") $hex .=  "3";
			if ($bin4=="0100") $hex .=  "4";
			if ($bin4=="0101") $hex .=  "5";
			if ($bin4=="0110") $hex .=  "6";
			if ($bin4=="0111") $hex .=  "7";
			if ($bin4=="1000") $hex .=  "8";
			if ($bin4=="1001") $hex .=  "9";
			if ($bin4=="1010") $hex .=  "A";
			if ($bin4=="1011") $hex .=  "B";
			if ($bin4=="1100") $hex .=  "C";
			if ($bin4=="1101") $hex .=  "D";
			if ($bin4=="1110") $hex .=  "E";
			if ($bin4=="1111") $hex .=  "F";
		}
		return $hex;
	}

	public static function hoanVi($input, $pc){
		$output = "";
		for ($i=0;$i<count($pc);$i++){
			$j = $pc[$i]-1;
			$output = $output . $input[$j];
		}
		return $output;
	}

	public static function cat2($input){
		$out1 = substr($input, 0, strlen($input)/2);
		$out2 = substr($input, strlen($input)/2, strlen($input)/2);
		$output = array();
		array_push($output, $out1, $out2);
		return $output;
	}

	public static function cat8($input){
		$len = strlen($input)/8;
		for ($i=0;$i<8;$i++){
			$output[$i] = substr($input, $i*$len, $len);
		}
		return $output;
	}

	public static function dichTrai($input, $bit){
		$out1 = substr($input, 0, $bit);
		$out2 = substr($input, $bit, strlen($input)-$bit);
		$output = $out2.$out1;
		return $output;
	}

	public static function dichPhai($input, $bit){
		$out1 = substr($input, 0, strlen($input)-$bit);
		$out2 = substr($input, strlen($input)-$bit, $bit);
		$output = $out2.$out1;
		return $output;
	}

	public static function phepXOR($binA, $binB){
		$output = "";
		for ($i=0;$i<strlen($binA);$i++){
			if ($binA[$i] == "0") {
				if ($binB[$i] == "0"){
					$output .= "0";
				}
				if ($binB[$i] == "1"){
					$output .= "1";
				}
			}
			if ($binA[$i] == "1") {
				if ($binB[$i] == "0"){
					$output .= "1";
				}
				if ($binB[$i] == "1"){
					$output .= "0";
				}
			}
		}
		return $output;
	}

	public static function toArray2Chieu($arr1){
		$len = count($arr1)/4;
		$k=0;
		for ($i=0;$i<4;$i++){
			for ($j=0; $j<$len;$j++){
				$arr2[$i][$j]=$arr1[$k++];
			}
		}
		return $arr2;
	}

	public static function binTo2Dec($input){
		$daucuoi = substr($input, 0,1) . substr($input, -1);
		$giua = substr($input, 1, -1);
		$daucuoi_dec = bindec($daucuoi);
		$giua_dec = bindec($giua);
		$output = array();
		array_push($output, $daucuoi_dec, $giua_dec);
		return $output;
	}

}
?>