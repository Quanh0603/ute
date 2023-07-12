<?php
include 'destable.php';
include 'convert.php';

function convertKeyToHex($input)
{
	$hex = convert::stringToHex($input);
	$len = strlen($hex);

	if ($len >= 16) {
		$hex = substr($hex, 0, 16);
	} else {
		$soKyTuThem = 16 - $len;
		$padding = str_repeat("0", $soKyTuThem);
		$hex .= $padding;
	}
	return $hex;
}

function Sbox($bit, $stt)
{
	$arr2Chieu = convert::toArray2Chieu(destable::${"s" . $stt});
	$arrDec = convert::binTo2Dec($bit);
	$hang = $arrDec[0];
	$cot = $arrDec[1];
	$output = convert::dec16ToBin($arr2Chieu[$hang][$cot]);
	return $output;
}

function hamF($R, $K)
{
	$Rmorong = convert::hoanVi($R, destable::$e);
	$xorRK = convert::phepXOR($Rmorong, $K);
	$catxorRK = convert::cat8($xorRK);
	$strSbox = "";
	for ($i = 1; $i <= 8; $i++) {
		$B[$i] = $catxorRK[$i - 1];
		$BS[$i] = Sbox($B[$i], $i);
		$strSbox .= $BS[$i];
	}
	$f = convert::hoanVi($strSbox, destable::$p);
	return $f;
}

function catNho($input)
{
	$lenInput = strlen($input);
	$soKyTuThem = 16 - $lenInput % 16;
	if ($soKyTuThem > 0 && $soKyTuThem < 16) {
		$padding = str_repeat("0", $soKyTuThem);
		$input_padding = $input . $padding;
	} else {
		$input_padding = $input;
	}
	$soKhoi = strlen($input_padding) / 16;
	$output = array();
	for ($i = 0; $i < $soKhoi; $i++) {
		$khoi = substr($input_padding, $i * 16, 16);
		array_push($output, $khoi);
	}
	return $output;
}

$cipherText = "";
$plainText = "";
$keyString = "";

// Xử lý mã hoá và hiển thị bản mã
if (isset($_POST['encrypt-btn'])) {
	$plainText = isset($_POST['plain-text']) ? $_POST['plain-text'] : '';
	$keyString = isset($_POST['encryption-key']) ? $_POST['encryption-key'] : '';
	$keyHex = convertKeyToHex($keyString);
	$key = $keyHex;

	$keyBin = convert::hexToBin($key);
	$keyPc1 = convert::hoanVi($keyBin, destable::$pc1);
	$catKey = convert::cat2($keyPc1);
	$C[0] = $catKey[0];
	$D[0] = $catKey[1];

	for ($i = 1; $i <= 16; $i++) {
		$bit = in_array($i, [1, 2, 9, 16]) ? 1 : 2;
		$C[$i] = convert::dichTrai($C[$i - 1], $bit);
		$D[$i] = convert::dichTrai($D[$i - 1], $bit);
		$CD[$i] = $C[$i] . $D[$i];
		$K[$i] = convert::hoanVi($CD[$i], destable::$pc2);
		$K_hex[$i] = convert::binToHex($K[$i]);
	}

	$hex_chuoi_can_ma_hoa = convert::stringToHex($plainText);
	$cacKhoi = catNho($hex_chuoi_can_ma_hoa);
	$soKhoi = count($cacKhoi);
	$banMa = "";
	for ($j = 0; $j < $soKhoi; $j++) {
		$x = $cacKhoi[$j];
		$x_bin = convert::hexToBin($x);
		$x_ip = convert::hoanVi($x_bin, destable::$ip);
		$catx = convert::cat2($x_ip);
		$L[0] = $catx[0];
		$R[0] = $catx[1];
		for ($i = 1; $i <= 16; $i++) {
			$L[$i] = $R[$i - 1];
			$F = hamF($R[$i - 1], $K[$i]);
			$R[$i] = convert::phepXOR($L[$i - 1], $F);
		}
		$R16L16 = $R[16] . $L[16];
		$y = convert::hoanVi($R16L16, destable::$ip_1);
		$y_hex = convert::binToHex($y);
		$banMa .= $y_hex;
	}
	$cipherText = $banMa;
} else {
	$cipherText = "";
}
// Xử lý giải mã
if (isset($_POST['decrypt-btn'])) {
	$cipherText = isset($_POST['cipher-text-input']) ? $_POST['cipher-text-input'] : '';
	$keyString = isset($_POST['encryption-key']) ? $_POST['encryption-key'] : '';
	$keyHex = convertKeyToHex($keyString);
	$key = $keyHex;

	$keyBin = convert::hexToBin($key);
	$keyPc1 = convert::hoanVi($keyBin, destable::$pc1);
	$catKey = convert::cat2($keyPc1);
	$C[0] = $catKey[0];
	$D[0] = $catKey[1];

	for ($i = 1; $i <= 16; $i++) {
		$bit = in_array($i, [1, 2, 9, 16]) ? 1 : 2;
		$C[$i] = convert::dichTrai($C[$i - 1], $bit);
		$D[$i] = convert::dichTrai($D[$i - 1], $bit);
		$CD[$i] = $C[$i] . $D[$i];
		$K[$i] = convert::hoanVi($CD[$i], destable::$pc2);
		$K_hex[$i] = convert::binToHex($K[$i]);
	}
	$decryptedText = "";
	// Xử lý giải mã cho từng khối bản mã
	$cacKhoi = catNho($cipherText);
	$soKhoi = count($cacKhoi);
	for ($j = 0; $j < $soKhoi; $j++) {
		$x = $cacKhoi[$j];
		$x_bin = convert::hexToBin($x);
		$x_ip = convert::hoanVi($x_bin, destable::$ip);
		$catx = convert::cat2($x_ip);
		$L[0] = $catx[0];
		$R[0] = $catx[1];
		for ($i = 1; $i <= 16; $i++) {
			$L[$i] = $R[$i - 1];
			$F = hamF($R[$i - 1], $K[17 - $i]); // Sử dụng K từ K16 đến K1
			$R[$i] = convert::phepXOR($L[$i - 1], $F);
		}
		$R16L16 = $R[16] . $L[16];
		$y = convert::hoanVi($R16L16, destable::$ip_1);
		$y_hex = convert::binToHex($y);
		$decryptedText .= $y_hex;
		echo $decryptedText;
	}
	$plainText = convert::hexToString($decryptedText);
} else {
	$plainText = "";
}
?>


<!DOCTYPE html>
<html>

<head>
	<title>Mã hoá và giải mã</title>
	<link rel="stylesheet" type="text/css" href="styles.css">
</head>

<body>
	<div class="container">
		<div class="left-section">
			<h1>Mã hoá</h1>
			<div class="input-section">
				<form method="post">
					<label for="plain-text-input">Bản rõ:</label>
					<textarea name="plain-text" id="plain-text-input" placeholder="Nhập bản rõ"><?php echo $plainText; ?></textarea>
					<label for="encryption-key-input">Khóa mã hoá:</label>
					<input type="text" name="encryption-key" id="encryption-key-input" placeholder="Nhập khóa mã hoá" value="<?php echo $keyString; ?>">
					<button type="submit" name="encrypt-btn">Mã hoá</button>
				</form>
				<div class="output">
					<label for="cipher-text-output">Bản mã:</label>
					<textarea id="cipher-text-output" readonly><?php echo $cipherText; ?></textarea>
				</div>
			</div>
		</div>
		<div class="right-section">
			<form method="post">
				<label for="cipher-text-input">Bản mã:</label>
				<textarea name="cipher-text-input" id="cipher-text-input" placeholder="Nhập bản mã"><?php echo $cipherText; ?></textarea>
				<button type="submit" name="decrypt-btn">Giải mã</button>
			</form>
			<div class="output">
				<label for="decrypted-text-output">Bản rõ:</label>
				<textarea id="decrypted-text-output" readonly><?php echo $plainText; ?></textarea>
			</div>
		</div>
	</div>
</body>

</html>