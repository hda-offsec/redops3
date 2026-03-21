from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.reporting import prepare_report_findings


def _report_finding():
    return {
        "id": "db-1",
        "id_stable": "stable-1",
        "title": "GraphQL schema leak",
        "severity": "high",
        "confidence": "high",
        "tool_source": "nuclei",
        "tool": "nuclei",
        "source": "nuclei",
        "module": "graphql_scanner",
        "category": "api",
        "description": "Introspection is still reachable on the public GraphQL endpoint.",
        "endpoint": "https://example.org/api/graphql",
        "target": "https://example.org/api/graphql",
        "parameter": "query",
        "raw_output": "HTTP/1.1 200 OK\n{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}}}}",
        "evidence": "Schema introspection returned the Query type.",
        "reproduction": "Validate that introspection stays enabled before blocking public access.",
        "remediation": "Disable introspection on public environments and restrict the endpoint.",
        "request": "GET /api/graphql?query={__schema} HTTP/1.1",
        "response": "HTTP/1.1 200 OK\ncontent-type: application/json",
        "impact": "Public schema exposure accelerates targeted abuse and enumeration.",
        "references": [
            "https://owasp.org/www-project-graphql-security-cheat-sheet/",
        ],
        "screenshot_path": "loot/graphql-proof.png",
        "metadata": {
            "provider": "aws",
            "component": "apigateway",
            "version": "2024.1",
            "versions": ["graphql-js 16.8.1"],
            "port_state": "open",
            "impact_area": "API Gateway",
            "artifacts": [{"header": "x-powered-by", "value": "graphql-js"}],
            "references": ["https://graphql.org/learn/security/"],
            "validation": {
                "status": "success",
                "result_state": "confirmed",
                "command": "curl -isk 'https://example.org/api/graphql?query={__schema}'",
                "target": "https://example.org/api/graphql",
                "artifact": "HTTP/1.1 200 OK",
            },
            "reproducibility": {
                "command": "nuclei -u https://fallback.example.org/graphql",
                "url": "https://fallback.example.org/graphql",
                "request_excerpt": "GET /api/graphql HTTP/1.1",
                "response_excerpt": "HTTP/1.1 200 OK\nx-powered-by: graphql-js",
            },
        },
    }


def _render_standard_report(findings):
    template_root = Path(__file__).resolve().parents[1] / "ui" / "web" / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_root)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.globals["url_for"] = lambda endpoint, **values: (
        f"/static/{values['filename']}"
        if endpoint == "static"
        else f"/scan/{values.get('scan_id', '')}/report?format={values.get('format', '')}"
    )
    template = env.get_template("reports/standard_report.html")
    return template.render(
        scan=SimpleNamespace(
            id=7,
            scan_type="full",
            status="completed",
            start_time=datetime(2026, 3, 21, 10, 0, 0),
            target=SimpleNamespace(identifier="example.org"),
        ),
        results={
            "phases": {
                "recon": {"open_ports": []},
                "enum": {
                    "api": {
                        "endpoints": [
                            "https://example.org/unverified",
                            {"url": "https://example.org/api/graphql", "status": 401},
                        ]
                    }
                },
            }
        },
        findings=prepare_report_findings(findings),
        suggestions=[],
        generated_at="2026-03-21 12:00:00",
        duration="00:15:00",
    )


def test_standard_report_preserves_rich_finding_detail_and_unverified_endpoint_status():
    html = _render_standard_report([_report_finding()])

    assert "Detailed Vulnerabilities" in html
    assert "Operational Summary" in html
    assert "Command & Validation" in html
    assert "Evidence & Raw Output" in html
    assert "Remediation" in html
    assert "References & Artifacts" in html
    assert "curl -isk &#39;https://example.org/api/graphql?query={__schema}&#39;" in html
    assert "graphql-js 16.8.1" in html
    assert "Disable introspection on public environments and restrict the endpoint." in html
    assert "https://graphql.org/learn/security/" in html
    assert "Unverified" in html
