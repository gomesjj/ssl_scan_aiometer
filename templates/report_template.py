REPORT_HTML = """
<!DOCTYPE html>
<html lang="en" cds-base-font="16">
<head>

  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta charset="UTF-8">
  <link rel="stylesheet" href="https://unpkg.com/@cds/city@1.1.0/css/bundles/default.min.css" />

  <title>{{VAR_TITLE}}</title>

<style>
body {
  background:#F4F4F4;
  color:#00608a;
  font-family:Helvetica, sans-serif, Arial;
  padding:0;
  text-align:left;
}
.tftable {
  border-collapse:collapse;
  border-color:white;
  color:#00608a;
  font-size:14px;
  font-weight:bold;
}
.tftable th {
  background-color:#00608a;
  border-color:white;
  border-style:solid;
  border-width:2px;
  color:white;
  padding:0.2rem;
  text-align:left;
}
.tftable tr.A {
  color:#42810e;
}
.tftable tr.B, tr.C, tr.D {
  color:#ffb92e;
}
.tftable tr.E, tr.F, tr.T {
  color:#e02200;
}
.tftable tr {
  background-color:#eeeeee;
}
.tftable tr:hover {
  background-color:#bdebff;
}
.tftable td {
  border-color:white;
  border-style:solid;
  border-width:2px;
  padding:0.4rem;
}

</style>

</head>
<body>
<h1>{{VAR_TITLE}}</h1>
<table class="tftable">
{{VAR_DATA}}
</table>
</body>
</html>
"""