##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_ssl_sec_bypass_vuln_win_900020.nasl 12460 2018-11-21 10:47:35Z cfischer $
#
# Pidgin NSS plugin SSL Certificate Validation Security Bypass Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:pidgin:pidgin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900020");
  script_version("$Revision: 12460 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 11:47:35 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3532");
  script_bugtraq_id(30553);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("Pidgin NSS plugin SSL Certificate Validation Security Bypass Vulnerability (Windows)");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");

  script_xref(name:"URL", value:"http://developer.pidgin.im/ticket/6500");
  script_xref(name:"URL", value:"http://developer.pidgin.im/attachment/ticket/6500/nss-cert-verify.patch");

  script_tag(name:"affected", value:"Pidgin Version 2.4.3 and prior on Windows (All).");

  script_tag(name:"insight", value:"The application fails to properly validate SSL (Secure Sockets Layer)
  certificate from a server.");

  script_tag(name:"summary", value:"The host is running Pidgin, which is prone to a Security Bypass
  Vulnerability");

  script_tag(name:"solution", value:"Apply the patch linked in the references.");

  script_tag(name:"impact", value:"Man-in-the-middle attacks or identity impersonation attacks are possible.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if( egrep( pattern:"^([01]\..*|2\.([0-3](\..*)?|4(\.[0-3])?))$", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
}

exit( 0 );
