###############################################################################
# OpenVAS Vulnerability Test
#
# Univention Corporate Server 4.0 erratum 142
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/o:univention:univention_corporate_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105249");
  script_cve_id("CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2019-12-05T15:10:00+0000");
  script_name("Univention Corporate Server 4.0 erratum 142");
  script_tag(name:"last_modification", value:"2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"creation_date", value:"2015-04-09 10:45:33 +0200 (Thu, 09 Apr 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ucs/errata", "ucs/version");

  script_xref(name:"URL", value:"http://errata.univention.de/ucs/4.0/142.html");

  script_tag(name:"vuldetect", value:"Checks for missing patches.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in OpenSSL:

  * NULL pointer dereference in elliptic curves (CVE-2015-0209)

  * Denial of service during certificate signature algorithm verification
  in ASN1_TYPE_cmp function (CVE-2015-0286)

  * Memory corruption in ASN.1 parsing (CVE-2015-0287)

  * NULL pointer dereference in X509 parsing (CVE-2015-0288)

  * Denial of service due to NULL pointer dereference in PKCS#7 parsing code
  (CVE-2015-0289)

  * Memory corruption due to missing input sanitising in base64 decoding
  (CVE-2015-0292)");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The remote host is missing an update for openssl (erratum 142)");

  script_tag(name:"affected", value:"Univention Corporate Server 4.0 erratum < 142");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) )
  if( ! version = get_kb_item( "ucs/version" ) ) exit( 0 );

if( version !~ "^4\.0" ) exit( 0 );

if( ! errata = get_kb_item("ucs/errata") ) exit( 0 );

if( int( errata ) < 142 ) {
  report = 'UCS version:           ' + version + '\n' +
           'Last installed errata: ' + errata + '\n' +
           'Fixed errata:          142\n';
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );
