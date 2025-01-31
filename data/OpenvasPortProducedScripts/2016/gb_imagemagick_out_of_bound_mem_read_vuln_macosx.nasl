###############################################################################
# OpenVAS Vulnerability Test
#
# ImageMagick Out Of Bounds Memory Read Vulnerability (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810256");
  script_version("2019-07-24T08:39:52+0000");
  script_cve_id("CVE-2016-5687");
  script_bugtraq_id(91283);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-24 08:39:52 +0000 (Wed, 24 Jul 2019)");
  script_tag(name:"creation_date", value:"2016-06-06 18:38:55 +0530 (Mon, 06 Jun 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick Out Of Bounds Memory Read Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with ImageMagick
  and is prone to an out of bounds memory read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out of bounds memory
  read in the 'VerticalFilter' function that can be triggered by a malformed DDS
  file.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to have unspecified impact.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.4-3
  and 7.x before 7.0.1-4 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  7.0.1-4 or 6.9.4-3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://blog.fuzzing-project.org/46-Various-invalid-memory-reads-in-ImageMagick-WPG,-DDS,-DCM.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/06/14/5");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"6.9.4.3"))
{
  fix = "6.9.4-3";
  VULN = TRUE;
}

else if(imVer =~ "^7\.")
{
  if(version_is_less(version:imVer, test_version:"7.0.1.4"))
  {
    fix = "7.0.1-4";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:fix);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
