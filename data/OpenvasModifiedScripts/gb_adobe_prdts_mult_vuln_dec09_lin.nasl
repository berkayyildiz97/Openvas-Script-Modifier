###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_dec09_lin.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Adobe Flash Player/Air Multiple Vulnerabilities - dec09 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801084");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3794", "CVE-2009-3796", "CVE-2009-3797", "CVE-2009-3798",
                "CVE-2009-3799", "CVE-2009-3800", "CVE-2009-3951");
  script_bugtraq_id(37266, 37270, 37273, 37275, 37267, 37269, 37272);
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities - dec09 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37584");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3456");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-19.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code,
  gain elevated privileges, gain knowledge of certain information and conduct clickjacking attacks.");

  script_tag(name:"affected", value:"Adobe AIR version prior to 1.5.3
  Adobe Flash Player 10 version prior to 10.0.42.34 on Linux");

  script_tag(name:"insight", value:"The multiple Flaws are due to:

  - An error occurred while parsing JPEG dimensions contained within an SWF file
    can be exploited to cause a heap-based buffer overflow.

  - An unspecified error may allow injection of data and potentially lead to
    execution of arbitrary code.

  - An unspecified error possibly related to 'getProperty()' can be exploited
    to corrupt memory and may allow execution of arbitrary code.

  - An unspecified error can be exploited to corrupt memory and may allow
    execution of arbitrary code.

  - An integer overflow error when generating ActionScript exception handlers
    in 'Verifier::parseExceptionHandlers()' can be exploited to corrupt memory.

  - Various unspecified errors may potentially allow execution of arbitrary code.

  - An error may disclose information about local file names.");

  script_tag(name:"solution", value:"Update to Adobe Air 1.5.3 or Adobe Flash Player 10.0.42.34.");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(playerVer != NULL)
{
  if(version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.42.33")){
    report = report_fixed_ver(installed_version:playerVer, vulnerable_range:"10.0" + " - " + "10.0.42.33");
    security_message(port: 0, data: report);
  }
}

airVer = get_kb_item("Adobe/Air/Linux/Ver");
if(airVer != NULL)
{
  if(version_is_less(version:airVer, test_version:"1.5.3")){
    report = report_fixed_ver(installed_version:airVer, fixed_version:"1.5.3");
    security_message(port: 0, data: report);
  }
}
