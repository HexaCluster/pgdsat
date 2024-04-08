package PGDSAT::Report;

#------------------------------------------------------------------------------
# Project  : PostgreSQL Database Security Assement Tool
# Name     : PGDSAT/Report.pm
# Language : Perl
# Authors  : Gilles Darold
# Copyright: Copyright (c) 2024 HexaCluster Corp
# Function : Module containing methods to build the report
#------------------------------------------------------------------------------
use vars qw($VERSION);
use strict;

$VERSION = '1.0';

####
# Build the report
####
sub generate_report
{
	my $self = shift;

	# Print the HTML header
	if ($self->{format} eq 'html') {
		begin_html($self);
	} else {
		$self->{content} = "POSTGRESQL SECURITY ASSESSEMENT REPORT \U$self->{title}\E\n\n";
	}


	# Add audit summary results
	if ($self->{format} eq 'text') {
		resume_as_text($self);
	} else {
		resume_as_html($self);
	}

	# Add the detailled result of the checks
	if ($self->{format} eq 'text')
	{
		$self->{content} .= "\n\n";
		$self->{content} .= "#"x80 . "\n";
		$self->{content} .= "# Detailled security assessment\n";
		$self->{content} .= "#"x80 . "\n\n";
	}
	else
	{
		$self->{content} .= "<hr>\n";
		$self->{content} .= "<table class=\"title\" width=\"100%\"><tr><td><h1 class=\"title\">Detailled security assessment</h1></td></tr></table>\n";
	}

	$self->{content} .= $self->{details};

	if ($self->{format} eq 'html') {
		end_html($self);
	} else {
		$self->{content} .= "\n(*) Check not part of the CIS Benchmark\n";
	}
}

####
# print the HTML header
####
sub begin_html
{
	my $self = shift;

	my $date = localtime(time);

	# Embedded logo
	my $pgdsat_logo = 'data:image/png;base64,
iVBORw0KGgoAAAANSUhEUgAAAEgAAABbCAYAAADQr8NyAAAAx3pUWHRSYXcgcHJvZmlsZSB0eXBlIGV4aWYAAHjabVBbDsMwCPvPKXaEBMiD46RrJ+0GO/6cQKu2qqWAg5FDCNvv+wmvAUoSJNdWtJQIiIpSB2nR0GdMUWackF1L13rIiwuEEiOzXVvx/r2eDgNLHSyfjNrbheUqqLh/uxn5QzwmIpDVjdSNmExIbtDtW7Foq+cvLFu8otkJI3Cd3ofJ/S4V21sziky0ceKIyFxsAB5HAncQRiTGUGgS8IzcwdQnwUKe9rQj/AE4HVla5u9k5QAAAYRpQ0NQSUNDIHByb2ZpbGUAAHicfZE9SMNAHMVfU6UiFQcLijhkqE4W1Io4ahWKUCHUCq06mFz6ITRpSFJcHAXXgoMfi1UHF2ddHVwFQfADxNnBSdFFSvxfUmgR48FxP97de9y9A4R6mWlWxxig6baZTibEbG5FDL0iiH6EMI64zCxjVpJS8B1f9wjw9S7Gs/zP/Tl61LzFgIBIPMMM0yZeJ57atA3O+8QRVpJV4nPiUZMuSPzIdcXjN85FlwWeGTEz6TniCLFYbGOljVnJ1IgniaOqplO+kPVY5bzFWStXWfOe/IXhvL68xHWaQ0hiAYuQIEJBFRsow0aMVp0UC2naT/j4B12/RC6FXBtg5JhHBRpk1w/+B7+7tQrxCS8pnAA6XxznYxgI7QKNmuN8HztO4wQIPgNXestfqQPTn6TXWlr0COjdBi6uW5qyB1zuAANPhmzKrhSkKRQKwPsZfVMO6LsFule93pr7OH0AMtRV6gY4OARGipS95vPurvbe/j3T7O8HwExyxoegtY8AAA8+aVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/Pgo8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJYTVAgQ29yZSA0LjQuMC1FeGl2MiI+CiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiCiAgICB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIKICAgIHhtbG5zOnN0RXZ0PSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VFdmVudCMiCiAgICB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iCiAgICB4bWxuczpHSU1QPSJodHRwOi8vd3d3LmdpbXAub3JnL3htcC8iCiAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgeG1wTU06RG9jdW1lbnRJRD0iZ2ltcDpkb2NpZDpnaW1wOjczZDgyNjA2LThhY2EtNGMzZS1hZDU4LTJjOTAwZDg5NDdmMyIKICAgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDo5MDQ5MTdiMC02ZWM2LTRlMDUtYmY2Ni0wNTIzMzNjYWQ2OTciCiAgIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDpiZGE1NzZlOS1hZDFiLTRjNDAtOTA1MS0wMjVmNzZlN2VhMGYiCiAgIGRjOkZvcm1hdD0iaW1hZ2UvcG5nIgogICBHSU1QOkFQST0iMi4wIgogICBHSU1QOlBsYXRmb3JtPSJMaW51eCIKICAgR0lNUDpUaW1lU3RhbXA9IjE3MTExODAzMDkyOTY2OTUiCiAgIEdJTVA6VmVyc2lvbj0iMi4xMC4zNiIKICAgdGlmZjpPcmllbnRhdGlvbj0iMSIKICAgeG1wOkNyZWF0b3JUb29sPSJHSU1QIDIuMTAiCiAgIHhtcDpNZXRhZGF0YURhdGU9IjIwMjQ6MDM6MjNUMTQ6NTE6NDkrMDc6MDAiCiAgIHhtcDpNb2RpZnlEYXRlPSIyMDI0OjAzOjIzVDE0OjUxOjQ5KzA3OjAwIj4KICAgPHhtcE1NOkhpc3Rvcnk+CiAgICA8cmRmOlNlcT4KICAgICA8cmRmOmxpCiAgICAgIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiCiAgICAgIHN0RXZ0OmNoYW5nZWQ9Ii8iCiAgICAgIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6YjYwMzUwMTAtODY5Yy00MDgyLWJhODQtMzM5ZmIwMDk4NTI3IgogICAgICBzdEV2dDpzb2Z0d2FyZUFnZW50PSJHaW1wIDIuMTAgKExpbnV4KSIKICAgICAgc3RFdnQ6d2hlbj0iMjAyNC0wMy0yMVQxNzoyMDoxNSswNzowMCIvPgogICAgIDxyZGY6bGkKICAgICAgc3RFdnQ6YWN0aW9uPSJzYXZlZCIKICAgICAgc3RFdnQ6Y2hhbmdlZD0iLyIKICAgICAgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDo2YWYyNGFjMi0xMDViLTQ2NTktYTM0NC00NTllYzg5YmM2NGIiCiAgICAgIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkdpbXAgMi4xMCAoTGludXgpIgogICAgICBzdEV2dDp3aGVuPSIyMDI0LTAzLTIxVDIzOjA4OjQwKzA3OjAwIi8+CiAgICAgPHJkZjpsaQogICAgICBzdEV2dDphY3Rpb249InNhdmVkIgogICAgICBzdEV2dDpjaGFuZ2VkPSIvIgogICAgICBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjA0ZmVmZWZhLWExMTMtNGM1MS1hYzM4LTNkODhmZjdkNjNlYyIKICAgICAgc3RFdnQ6c29mdHdhcmVBZ2VudD0iR2ltcCAyLjEwIChMaW51eCkiCiAgICAgIHN0RXZ0OndoZW49IjIwMjQtMDMtMjNUMTQ6NTE6NDkrMDc6MDAiLz4KICAgIDwvcmRmOlNlcT4KICAgPC94bXBNTTpIaXN0b3J5PgogIDwvcmRmOkRlc2NyaXB0aW9uPgogPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg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
';

        $self->{content} .= qq{<!DOCTYPE html>
<html lang="$self->{lang}">
<head>
<title>pgdsat report</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf8" />
<meta name="robots" content="noindex,nofollow">
<meta http-equiv="Expires" content="$date">
<meta http-equiv="Generator" content="pgdsat v$VERSION">
<meta http-equiv="Date" content="$date">
<link rel="shortcut icon" href="$pgdsat_logo" />
<!-- Font Awesome Icon Library -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<style>
body { background: #ffffff; margin-top: 50px; margin-left: 50px; margin-right: 50px; }
.footer { background-color:#1a4480; color: #ffffff; margin-top: 15px; }
.title { background-color:#005ea2; color: #ffffff; margin-right: 25px; }
.collapse { display:none; }
hr { margin-top: 20px; margin-bottom: 20px; }
h1, h2, h3 { color: #1a4480; }
a { color: #565656; }
a:visited { color: #565656; }
a:hover { color: #1a4480;}
table { border-collapse: collapse; border-spacing: 0; border: 1px solid #cccccc; }
th { background: #dddddd; }
th, td { margin: 15px; border: 1px solid #cccccc; padding-left: 15px; padding-right: 15px; }
.alert {
    border: 0px;
    font-size: 1.0em;
    font-weight: bold;
    margin: 5px;
    padding: 5px;
    color:#ffffff;
    background: #5f5555;
    border:1px solid #5f5555;
    border:1px solid rgba(0, 0, 0, 0.2);
    -webkit-border-radius:6px;
    -moz-border-radius:6px;
    border-radius:6px;
    -webkit-box-shadow:0 5px 10px rgba(0, 0, 0, 0.2);
    -moz-box-shadow:0 5px 10px rgba(0, 0, 0, 0.2);
    box-shadow:0 5px 10px rgba(0, 0, 0, 0.2);
}
.alert.success { background-color: #04AA6D; }
.alert.info { background-color: #2196F3; }
.alert.warning { background-color: #ff9800; }
.alert.critical { background-color: #f44336; }
.alert.error { background-color: #f44336; }

.fa-check { color: green; }
.fa-remove { color: red; }
.fa-square-o { color: black; }
</style>

<script>
function collapseme(elmt)
{
        var x = document.getElementById(elmt);
        if (x.style.display === "block") {
                x.style.display = "none";
        } else {
                x.style.display = "block";
        }
}
</script>
</head>
<body>
<table style="border: 0px;" class="title">
<tr style="border: 0px;"><td style="border: 0px; text-align: left;"><img src="$pgdsat_logo" width="100px" /></td><td style="border: 0px;"><h1 class="title">PostgreSQL Security Assessement Report<br>$self->{title}</h1></td></tr>
</table>

};

}

####
# End the HTML page
####
sub end_html
{
	my $self = shift;

	$self->{content} .= qq{
	<p><small>(*) Check not part of the CIS Benchmark</small></p>
<table class="footer" width="100%">
	<tr><td style="padding-top: 10px; padding-bottom: 10px;">
	<small class="pull-left"><strong>Copyright &copy; 2024 : <a href="https://hexacluster.ai/" target="_new" style="color: #ffffff;text-decoration:none;">HexaCluster Corp</a></strong></small>
	</td><td>
	<small class="pull-right"><strong>Report generated by <a href="https://github.com/HexaCluster/pgdsat/" target="_new" style="color: #ffffff;text-decoration:none;">pgdsat v$VERSION.</a></strong></small>
	</td></tr>
</table>

</body>
</html>
};

}

####
# Create the resume of the assessment in TEXT format
####
sub resume_as_text
{
	my $self = shift;

	$self->{content} .= "#"x80 . "\n";
	$self->{content} .= "# Summary Table of security checks\n";
	$self->{content} .= "#"x80 . "\n\n";
	foreach my $level (sort {
				my @left = (0,0,0);
				my @right = (0,0,0);
				my @tmp = split(/\./, $a);
				for (my $i = 0; $i <= $#tmp; $i++) {
					$left[$i] = $tmp[$i];
				}
				@tmp = split(/\./, $b);
				for (my $i = 0; $i <= $#tmp; $i++) {
					$right[$i] = $tmp[$i];
				}
				"$left[0]." . sprintf("%02d", $left[1]) . sprintf("%02d", $left[2]) <=> "$right[0]." . sprintf("%02d", $right[1]) . sprintf("%02d", $right[2])

			} keys %{ $PGDSAT::Labels::AUDIT_LBL{$self->{lang}} } )
	{
		next if (!exists $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{title});
		my $manual = ' (Manual)';
		$manual = '' if (!$PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{manual});
		$self->{content} .= "$level - $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{title}$manual";
		if (!exists $self->{results}{$level} || ($manual && $self->{results}{$level} ne 'FAILURE')) {
			$self->{content} .= "\n";
		} else {
			$self->{content} .= " => $self->{results}{$level}\n";
		}
	}
}

####
# Create the resume of the assessment in HTML format
####
sub resume_as_html
{
	my $self = shift;

	$self->{content} .= "<h1>Summary Table of security checks</h1>\n";
	$self->{content} .= "<table>\n";
	$self->{content} .= "<tr><th colspan=\"2\" align=\"left\">CIS Benchmark Recommendation</th><th>Set Correctly</th></tr>\n";
	foreach my $level (sort {
				my @left = (0,0,0);
				my @right = (0,0,0);
				my @tmp = split(/\./, $a);
				for (my $i = 0; $i <= $#tmp; $i++) {
					$left[$i] = $tmp[$i];
				}
				@tmp = split(/\./, $b);
				for (my $i = 0; $i <= $#tmp; $i++) {
					$right[$i] = $tmp[$i];
				}
				"$left[0]." . sprintf("%02d", $left[1]) . sprintf("%02d", $left[2]) <=> "$right[0]." . sprintf("%02d", $right[1]) . sprintf("%02d", $right[2])

			} keys %{ $PGDSAT::Labels::AUDIT_LBL{$self->{lang}} } )
	{
		next if (!exists $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{title});
		my $manual = ' (Manual)';
		$manual = '' if (!$PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{manual});
		my $num = () = $level =~ /\./g;
		my $tab = "&nbsp;" x ($num * 2);
		if ($level =~ /^\d+$/) {
			$self->{content} .= "<tr><th align=\"left\">$tab$level</th><th colspan=\"2\" align=\"left\">$tab<a style=\"text-decoration: none;\" href=\"#$level\">$PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{title}$manual</a></th></tr>\n";
		} else {
			$self->{content} .= "<tr><td>$tab$level</td><td>$tab<a style=\"text-decoration: none;\" href=\"#$level\">$PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{title}$manual</a></td><td align=\"center\">";
			if (!exists $self->{results}{$level}) {
				$self->{content} .= "&nbsp\n";
			} elsif ($manual && $self->{results}{$level} ne 'FAILURE') {
				$self->{content} .= "<i class=\"fa fa-square-o\"></i>";
			} else {
				if ($self->{results}{$level} eq 'FAILURE') {
					$self->{content} .= "<i class=\"fa fa-remove\"></i>";
				} elsif ($self->{results}{$level} eq 'SUCCESS') {
					$self->{content} .= "<i class=\"fa fa-check\"></i>";
				}
			}
			$self->{content} .= "</td></tr>\n";
		}
	}
	$self->{content} .= "</table>\n";
}

####
# Write the report to stdout or file following the options used
####
sub save_report
{
	my $self = shift;

	my $fh;
	if ( $self->{output} ne '-' ) {
		open $fh, '>', $self->{output} or die "FATAL: can't write to file $self->{output}, $!\n";
	} else {
		$fh = \*STDOUT;
	}
	print $fh $self->{content};
	close $fh if ( $self->{output} ne '-' );

	return;
}

1;
