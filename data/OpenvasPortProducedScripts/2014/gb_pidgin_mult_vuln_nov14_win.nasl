###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_mult_vuln_nov14_win.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Pidgin Multiple Vulnerabilities Nov 2014 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:pidgin:pidgin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804890");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-3694", "CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3697",
                "CVE-2014-3698");
  script_bugtraq_id(70701, 70702, 70705, 70704, 70703);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-21 18:58:24 +0530 (Fri, 21 Nov 2014)");
  script_name("Pidgin Multiple Vulnerabilities Nov 2014 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Pidgin and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exists due to,

  - An error when parsing XMPP messages.

  - An error when unpacking smiley themes.

  - Improper verification of the Basic Constraints of an SSL certificate.

  - An error when handling Groupwise message.

  - An error when handling of an MXit emoticon.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service (crash), disclosure of potentially sensitive
  information, disclose and manipulate certain data and spoofing attacks.");

  script_tag(name:"affected", value:"Pidgin before version 2.10.10 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.10.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=86");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=87");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=88");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=89");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=90");

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_xref(name:"URL", value:"http://www.pidgin.im/");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!pidVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:pidVer, test_version:"2.10.0", test_version2:"2.10.9"))
{
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  exit(0);
}
