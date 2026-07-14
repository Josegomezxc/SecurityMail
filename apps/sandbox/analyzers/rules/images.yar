

rule IMG_SVG_ScriptTag {
	meta:
		description = "SVG con etiqueta <script> — posible JavaScript malicioso embebido"
		author = "email_seguro"
		score = 85
		category = "image_svg"
	strings:
		$svg_header = /<svg[\s>]/i
		$script_tag = /<script[\s>]/i
	condition:
		$svg_header and $script_tag
}

rule IMG_SVG_EventHandler {
	meta:
		description = "SVG con event handlers inline (onload, onerror, onclick) — posible XSS"
		author = "email_seguro"
		score = 80
		category = "image_svg"
	strings:
		$svg_header = /<svg[\s>]/i
		$evt = /on(load|error|click|mouseover|focus|submit|change)\s*=/i
	condition:
		$svg_header and $evt
}

rule IMG_SVG_ForeignObject {
	meta:
		description = "SVG con <foreignObject> — puede contener HTML/JavaScript embebido"
		author = "email_seguro"
		score = 70
		category = "image_svg"
	strings:
		$fo = /<foreignObject[\s>]/i
	condition:
		$fo
}

rule IMG_SVG_DataURI_JS {
	meta:
		description = "SVG con data:text/javascript en href/src — ejecución de código"
		author = "email_seguro"
		score = 85
		category = "image_svg"
	strings:
		$data_js = /data\s*:\s*text\/javascript/i
	condition:
		$data_js
}

rule IMG_SVG_ExternalRef {
	meta:
		description = "SVG con referencia externa (<image href=http>, <use href=http>) — posible fuga de datos"
		author = "email_seguro"
		score = 50
		category = "image_svg"
	strings:
		$svg_header = /<svg[\s>]/i
		$ext_href = /(href|src)\s*=\s*["']https?:\/\//i
	condition:
		$svg_header and $ext_href
}

rule IMG_ImageTragick_MVG {
	meta:
		description = "Posible exploit ImageMagick — contenido MVG en SVG/imagen"
		author = "email_seguro"
		score = 80
		category = "image_exploit"
	strings:
		$mvg = /push\s+(graphics|defs|pattern)/i
		$im_cmd = /("|\|)\s*(convert|identify|mogrify)\s/i
	condition:
		$mvg or $im_cmd
}

rule IMG_GhostScript_Exploit {
	meta:
		description = "Patrón de PostScript malicioso (CVE-2023-36664 y similares)"
		author = "email_seguro"
		score = 80
		category = "image_exploit"
	strings:
		$ps_cmd = /(%pipe|system|run)\s*\(/i
		$ps_output = /output\s+file\s*\(/i
	condition:
		$ps_cmd or $ps_output
}

rule IMG_TrackingPixel_1x1 {
	meta:
		description = "Imagen de 1x1 píxel — posible pixel de tracking/web bug"
		author = "email_seguro"
		score = 10
		category = "image_tracking"
	strings:
		$gif = { 47 49 46 38 39 61 01 00 01 00 }
		$gif87 = { 47 49 46 38 37 61 01 00 01 00 }
		$png = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 00 01 00 00 00 01 }
		$bmp = { 42 4D 3A 00 00 00 00 00 00 00 36 00 00 00 28 00 00 00 01 00 00 00 01 00 00 00 }
	condition:
		$gif at 0 or $gif87 at 0 or $png at 0 or $bmp at 0
}

rule IMG_Malformed_JPEG {
	meta:
		description = "JPEG con estructura sospechosa — posible exploit"
		author = "email_seguro"
		score = 60
		category = "image_exploit"
	strings:
		$jpeg = { FF D8 FF }
		$multiple_soi = { FF D8 FF FF D8 FF }
		$eoi_early = { FF D9 00 00 FF D8 }
	condition:
		$jpeg at 0 and ($multiple_soi or $eoi_early)
}

rule IMG_Malformed_PNG_Chunks {
	meta:
		description = "PNG con chunks anómalos — posible stego o exploit"
		author = "email_seguro"
		score = 50
		category = "image_exploit"
	strings:
		$png = { 89 50 4E 47 0D 0A 1A 0A }
		$chunk_cArI = { 63 41 72 49 }  
		$chunk_evil = { 65 76 69 6C }   
		$extra_data = /[^\x00]{200,}$/  
	condition:
		$png at 0 and ($chunk_cArI or $chunk_evil or $extra_data)
}
