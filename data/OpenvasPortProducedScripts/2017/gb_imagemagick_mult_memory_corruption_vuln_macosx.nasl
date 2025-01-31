###############################################################################
# OpenVAS Vulnerability Test
#
# ImageMagick Multiple Memory Corruption Vulnerabilities (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810563");
  script_version("2019-07-05T10:41:31+0000");
  script_cve_id("CVE-2016-8862", "CVE-2016-8866");
  script_bugtraq_id(93794);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2017-02-21 13:23:30 +0530 (Tue, 21 Feb 2017)");
  script_name("ImageMagick Multiple Memory Corruption Vulnerabilities (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with ImageMagick
  and is prone to multiple memory corruption vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to
  memory corruption error in 'AcquireMagickMemory' function in
  MagickCore/memory.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause some unspecified impacts.");

  script_tag(name:"affected", value:"ImageMagick version before 7.0.3.8
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version 7.0.3.8
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/10/17/imagemagick-memory-allocation-failure-in-acquiremagickmemory-memory-c");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/10/20/imagemagick-memory-allocation-failure-in-acquiremagickmemory-memory-c-incomplete-fix-for-cve-2016-8862");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/10/20/3");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

## CVE-2016-8866 is due to an incomplete fix for CVE-2016-8862
## CVE-2016-8862 , not fixed completely in 7.0.3.3, complete fix is in 7.0.3.8
if(version_is_less(version:gmVer, test_version:"7.0.3.8"))
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"7.0.3.8");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
