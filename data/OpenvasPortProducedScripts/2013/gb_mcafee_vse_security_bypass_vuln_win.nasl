##############################################################################
# OpenVAS Vulnerability Test
#
# McAfee VirusScan Enterprise Security Bypass Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803321");
  script_version("2019-12-18T15:04:04+0000");
  script_cve_id("CVE-2010-3496");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-12-18 15:04:04 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2013-03-04 10:50:36 +0530 (Mon, 04 Mar 2013)");
  script_name("McAfee VirusScan Enterprise Security Bypass Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
  via malware that is correctly detected by this product.");

  script_tag(name:"affected", value:"McAfee VirusScan Enterprise versions 8.5i and 8.7i");

  script_tag(name:"insight", value:"Does not properly interact with the processing of hcp:// URLs by the
  Microsoft Help and Support Center.");

  script_tag(name:"summary", value:"This host is installed with McAfee VirusScan Enterprise and is
  prone to security bypass vulnerability.");

  script_tag(name:"solution", value:"Apply the patch.");
  script_tag(name:"qod", value:"30");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2010-3496");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10012");
  script_xref(name:"URL", value:"http://go.microsoft.com/fwlink/?LinkId=194729");

  exit(0);
}

CPE = "cpe:/a:mcafee:virusscan_enterprise";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version == "8.5i"|| version == "8.7i" ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Apply the patch", install_path: location );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit( 99 );
