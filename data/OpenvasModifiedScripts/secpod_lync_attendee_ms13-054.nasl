###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Lync Attendee Remote Code Execution Vulnerability (2848295)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902981");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2013-3129");
  script_bugtraq_id(60978);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2013-07-10 12:56:53 +0530 (Wed, 10 Jul 2013)");
  script_name("Microsoft Lync Attendee Remote Code Execution Vulnerability (2848295)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54057/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2843162");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2843163");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028750");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-054");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_ms_lync_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Lync/Attendee/Ver", "MS/Lync/Attendee/path");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user.");

  script_tag(name:"affected", value:"Microsoft Lync Attendee 2010");

  script_tag(name:"insight", value:"The flaw is due to an error when processing TrueType fonts and can be
  exploited to cause a buffer overflow via a specially crafted file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-054.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## For Microsoft Lync 2010 Attendee (admin level install)
## For Microsoft Lync 2010 Attendee (user level install)
if(get_kb_item("MS/Lync/Attendee/Ver"))
{
  path = get_kb_item("MS/Lync/Attendee/path");
  if(path)
  {
    oglVer = fetch_file_version(sysPath:path, file_name:"Ogl.dll");
    if(oglVer)
    {
      if(version_in_range(version:oglVer, test_version:"4.0", test_version2:"4.0.7577.4391"))
      {
        report = report_fixed_ver(installed_version:oglVer, vulnerable_range:"4.0" + " - " + "4.0.7577.4391", install_path:path);
        security_message(port: 0, data: report);
        exit(0);
      }
    }
  }
}
