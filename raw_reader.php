<?php
class raw_reader extends basic {
	
	var $readFrom;
	
	var $pointer;
	

	function set_readFrom(&$varRef) {
		
		$this->readFrom = &$varRef;
		$this->pointer = 0;
		
	}
	
	function fget_byte() {

		$byte = ord($this->readFrom[$this->pointer]);

        $this->pointer++;

		return $byte;
	}


	/**
	 * Reads two bytes from the data stream and casts it into
	 * an integer value.
	 *
	 * The red bytes are merged into one value so they are
	 * easy to use.
	 *
	 * @return int The resulting int value
	 * @access private
	 * @see php2icq::fget_byte(), php2icq::fget_dword(), php2icq::fget_string(), php2icq::fget_dummy_bytes(), php2icq::fget_dummy_packet()
	 */
	function fget_word()
	{
		$byte_m = ord($this->readFrom[$this->pointer]);

        $this->pointer++;

		$byte_l = ord($this->readFrom[$this->pointer]);

        $this->pointer++;

		return (0x100 * $byte_m) + $byte_l;
	}


	/**
	 * Reads four bytes from the data stream and casts it into
	 * an integer value.
	 *
	 * The red bytes are merged into one value so they are
	 * easy to use.
	 *
	 * @return int The resulting int value
	 * @access private
	 * @see php2icq::fget_byte(), php2icq::fget_word(), php2icq::fget_string(), php2icq::fget_dummy_bytes(), php2icq::fget_dummy_packet()
	 */
	function fget_dword()
	{
		$byte_1 = ord($this->readFrom[$this->pointer]);
        $this->pointer++;

		$byte_2 = ord($this->readFrom[$this->pointer]);
        $this->pointer++;

		$byte_3 = ord($this->readFrom[$this->pointer]);
        $this->pointer++;

		$byte_4 = ord($this->readFrom[$this->pointer]);
        $this->pointer++;

		return (0x1000000 * $byte_1) + (0x10000 * $byte_2) + (0x100 * $byte_3) + $byte_4;
	}


	/**
	 * Reads multiple bytes from the datastream and saves
	 * them as a string.
	 *
	 * The red bytes are simply saved as a string. This function
	 * is usefull for reading (ascii) text, but not for numbers you want to operate with.
	 *
	 * @param int How many bytes will be read
	 * @return string The resulting data string
	 * @access private
	 * @see php2icq::fget_byte(), php2icq::fget_word(), php2icq::fget_dword(), php2icq::fget_dummy_bytes(), php2icq::fget_dummy_packet()
	 */
	function fget_string($anzahl_bytes)
	{
		$str = substr($this->readFrom, $this->pointer, $anzahl_bytes);
        $this->pointer+= $anzahl_bytes;

		return $str;
	}

	function fget_hex_string($anzahl_bytes)
	{

    	$hex = '';
    	for($i = 0; $i <$anzahl_bytes; $i++ ){

        	$h = dechex(ord($this->readFrom[$this->pointer + $i]));
        	$hex .= strlen($h) ==2 ? $h : '0'.$h;
        }

        $this->pointer+= $anzahl_bytes;


		return $hex;
	}


	/**
	 * Reads multiple bytes from the datastream without
	 * saving them anywhere.
	 *
	 * Usefull for moving the data pointer.
	 *
	 * @param int How many bytes will be overread
	 * @access private
	 * @see php2icq::fget_byte(), php2icq::fget_word(), php2icq::fget_dword(), php2icq::fget_string(), php2icq::fget_dummy_packet()
	 */
	function fget_dummy_bytes($anzahl_bytes)
	{
		$this->fget_string($anzahl_bytes);
	}


	/**
	 * Simply overreads a whole packet.
	 *
	 * Usefull for moving the data pointer.
	 *
	 * @param int How many bytes will be overread
	 * @return bool True if success. False if failure (eg. Unexpected bytes etc.).
	 * @access private
	 * @see php2icq::fget_byte(), php2icq::fget_word(), php2icq::fget_dword(), php2icq::fget_string(), php2icq::fget_dummy_bytes()
	 */
	function fget_dummy_packet($flap_channel)
	{
		// Proof FLAP header and get length of the body
		if (!($flap_length = $this->check_flap_header($flap_channel)))
		{
			return false;
		}

		// Overread the whole body
		$this->fget_dummy_bytes($flap_length);

		return true;
	}	
	
}
?>