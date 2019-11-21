###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pwhois_lft_unspecified_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# pWhois Layer Four Traceroute (LFT) Unspecified Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801915");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-1652");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("pWhois Layer Four Traceroute (LFT) Unspecified Vulnerability");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/946652");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain privileges.");
  script_tag(name:"affected", value:"pWhois Layer Four Traceroute (LFT) 3.x before 3.3");
  script_tag(name:"insight", value:"An unspecified vulnerability exists in application, which allows local users
  to gain privileges via a crafted command line.");
  script_tag(name:"solution", value:"Upgrade Layer Four Traceroute to 3.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Whois Layer Four Traceroute (LFT) and
  is prone to unspecified vulnerability.");
  script_xref(name:"URL", value:"http://pwhois.org/lft/");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

paths = find_bin(prog_name:"lft", sock:sock);
foreach bin (paths)
{
  lftVer = get_bin_version(full_prog_name:chomp(bin), sock:sock, version_argv:"-v",
                           ver_pattern:"version ([0-9.]+)");

  if(lftVer[1] != NULL)
  {
    if(version_in_range(version:lftVer[1], test_version:"3.0", test_version2:"3.2"))
    {
      report = report_fixed_ver(installed_version:lftVer[1], vulnerable_range:"3.0" + " - " + "3.2");
      security_message(port: 0, data: report);
      close(sock);
      exit(0);
    }
    ssh_close_connection();
  }
}
close(sock);
ssh_close_connection();
