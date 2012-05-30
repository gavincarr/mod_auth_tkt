#
# auth_tkt.tcl
#
# Author: David McNett - http://macnugget.org/
# Date:   29-May-2012
#
# See http://www.openfusion.com.au/labs/mod_auth_tkt/ for more detail
#

package require sha256

namespace eval ::auth_tkt {

	proc logerr {buf} {
		puts stderr "ERROR (auth_tkt): $buf"
	}

	proc get_secret_key {filename} {
		set retbuf ""

		if {![file exists $filename]} {
			logerr "Unable to locate secret key file $filename"
		} else {
			if {[catch {set fh [open $filename r]} err]} {
				logerr "Unable to read secret key file $err"
			} else {
				while {1} {
					set line [gets $fh]
						if {[regexp -nocase {^\s*TKTAuthSecret\s+"?(.*?)"?} $line _ retbuf] || [eof $fh]} {
						close $fh
						break
					}
				}
				return $retbuf
			}
		}
	}

	proc get_tkt_to_array {arrvar args} {
		#
		# required arguments:
		#    -ip			Either the user's IP or 0.0.0.0
		#    -user			User ID
		#    -key			Shared Private Key
		#
		# optional arguments:
		#    -tokenlist		Tcl list of tokens
		#    -data			User data
		#

		if {[catch {array set opts $args} err]} {
			logerr "Invalid get_tkt_hash arguments"
			return
		}

		foreach required_field {-ip -user -key} {
			if {![info exists opts($required_field)]} {
				logerr "get_tkt_hash required argument missing: $required_field"
				return
			}
		}

		upvar 1 $arrvar outarray

		foreach optional_field {-tokenlist -data} {
			if {![info exists opts($optional_field)]} {
				set opts($optional_field) ""
			}
		}

		if {[info exists opts(-timestamp)] && [ctype digit $opts(-timestamp)]} {
			set timestamp	$opts(-timestamp)
		} else {
			set timestamp	[clock seconds]
		}
		set hextimestamp [format "%8.8X" $timestamp]
		set iptstamp     [binary format II 0 $timestamp]

		set outarray(payload0) "${iptstamp}$opts(-key)$opts(-user)\0[join $opts(-tokenlist) ","]\0$opts(-data)"
		set outarray(digest0)  [::sha2::sha256 $outarray(payload0)]
		set outarray(digest)   [::sha2::sha256 "$outarray(digest0)$opts(-key)"]
		set outarray(cookie)   "$outarray(digest)${hextimestamp}$opts(-user)![join $opts(-tokenlist) ","]!$opts(-data)"
	}
}

package provide auth_tkt 1.0
