###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Shockwave Player Multiple Vulnerabilities-01 Sep13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804002");
  script_version("2019-09-24T14:07:14+0000");
  script_cve_id("CVE-2013-3359", "CVE-2013-3360");
  script_bugtraq_id(62291, 62292);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-24 14:07:14 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2013-09-18 19:24:31 +0530 (Wed, 18 Sep 2013)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities-01 Sep13 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Shockwave Player and is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to version 12.0.4.144 or later.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error when parsing dir files with a malformed field.

  - Another unspecified error.");

  script_tag(name:"affected", value:"Adobe Shockwave Player before 12.0.4.144 on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code, cause
  memory corruption and compromise a user's system.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54700");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb13-23.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"12.0.4.144")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.0.4.144");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
