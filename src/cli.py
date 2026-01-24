"""Threat Model Tool - Command Line Interface."""

import sys
from pathlib import Path
from datetime import datetime
import click

from .parser import load_threat_model, discover_threat_models, calculate_relative_path, ThreatModelParseError
from .report_generator import ReportGenerator
from .dfd_generator import DFDGenerator
from .attack_tree import AttackTreeGenerator
from .analyzer import ThreatModelGenerator


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """Threat Model Tool - Structured threat modeling platform."""
    pass


@cli.command()
@click.argument('model_path', type=click.Path(exists=True, file_okay=False, dir_okay=True))
def validate(model_path: str):
    """Validate a threat model folder."""
    try:
        model = load_threat_model(model_path)
        click.echo(click.style('Validation successful!', fg='green'))
        click.echo(f'  Model: {model.meta.title}')
        click.echo(f'  ID: {model.meta.modelId}')
        click.echo(f'  Version: {model.meta.version}')
        click.echo(f'  Assets: {len(model.assets)}')
        click.echo(f'  Threats: {len(model.threats)}')
        click.echo(f'  Attackers: {len(model.attackers)}')
        click.echo(f'  Security Objectives: {len(model.securityObjectives)}')
    except ThreatModelParseError as e:
        click.echo(click.style(f'Validation failed: {e}', fg='red'), err=True)
        sys.exit(1)


@cli.command()
@click.argument('model_path', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--output', '-o', type=click.Path(), help='Output HTML file path')
@click.option('--models-root', type=click.Path(exists=True), help='Root folder containing all threat models')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def report(model_path: str, output: str, models_root: str, verbose: bool):
    """Generate an HTML report for a threat model."""
    try:
        if verbose:
            click.echo(f'[INFO] Loading threat model from: {model_path}')
        
        model = load_threat_model(model_path)
        model_path = Path(model_path).resolve()
        
        if output:
            output_path = Path(output).resolve()
        else:
            output_path = model_path / 'reports' / 'threat-model.html'
        
        if not models_root:
            potential_root = model_path.parent
            if potential_root.exists():
                models_root = str(potential_root)
        
        all_models = []
        if models_root:
            current_model_path = model_path
            models_root_path = Path(models_root).resolve()
            
            for model_folder in discover_threat_models(models_root):
                try:
                    model_folder = model_folder.resolve()
                    other_model = load_threat_model(model_folder)
                    rel_path = f'../../{model_folder.name}/reports/threat-model.html'
                    is_current = model_folder == current_model_path
                    
                    if verbose:
                        click.echo(f'[INFO] Found model: {other_model.meta.title}')
                    
                    all_models.append({
                        'title': other_model.meta.title,
                        'modelId': other_model.meta.modelId,
                        'reportPath': rel_path,
                        'isCurrent': is_current
                    })
                except ThreatModelParseError:
                    continue
                except Exception:
                    continue
        
        all_models.sort(key=lambda x: x['title'])
        
        generator = ReportGenerator()
        generator.generate_to_file(model, output_path, all_models if all_models else None)
        
        click.echo(click.style('Report generated successfully!', fg='green'))
        click.echo(f'  Output: {output_path}')
        
    except ThreatModelParseError as e:
        click.echo(click.style(f'Failed to generate report: {e}', fg='red'), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f'Unexpected error: {e}', fg='red'), err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


@cli.command()
@click.argument('model_path', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', 'output_format', type=click.Choice(['svg', 'png', 'pdf', 'dot', 'mermaid']), default='svg')
def dfd(model_path: str, output: str, output_format: str):
    """Generate a Data Flow Diagram for a threat model."""
    try:
        model = load_threat_model(model_path)
        
        if not model.assets:
            click.echo(click.style('No assets defined in this threat model.', fg='yellow'))
            return
        
        generator = DFDGenerator(model)
        
        if output_format == 'mermaid':
            mermaid_output = generator.to_mermaid()
            if output:
                Path(output).write_text(mermaid_output)
                click.echo(click.style(f'DFD generated: {output}', fg='green'))
            else:
                click.echo(mermaid_output)
        elif output_format == 'dot':
            dot_output = generator.generate_dot()
            if output:
                Path(output).write_text(dot_output)
                click.echo(click.style(f'DFD generated: {output}', fg='green'))
            else:
                click.echo(dot_output)
        else:
            if output:
                output_file = generator.render_to_file(output, output_format)
                click.echo(click.style(f'DFD generated: {output_file}', fg='green'))
            else:
                output_path = Path(model_path) / 'reports' / 'dfd'
                output_file = generator.render_to_file(str(output_path), output_format)
                click.echo(click.style(f'DFD generated: {output_file}', fg='green'))
        
    except ThreatModelParseError as e:
        click.echo(click.style(f'Failed to generate DFD: {e}', fg='red'), err=True)
        sys.exit(1)


@cli.command()
@click.argument('model_path', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', 'output_format', type=click.Choice(['svg', 'png', 'pdf', 'dot', 'mermaid', 'text']), default='svg')
def attack_tree(model_path: str, output: str, output_format: str):
    """Generate an Attack Tree for a threat model."""
    try:
        model = load_threat_model(model_path)
        
        if not model.threats:
            click.echo(click.style('No threats defined in this threat model.', fg='yellow'))
            return
        
        generator = AttackTreeGenerator(model)
        
        if output_format == 'mermaid':
            mermaid_output = generator.to_mermaid()
            if output:
                Path(output).write_text(mermaid_output)
                click.echo(click.style(f'Attack tree generated: {output}', fg='green'))
            else:
                click.echo(mermaid_output)
        elif output_format == 'text':
            text_output = generator.to_text()
            if output:
                Path(output).write_text(text_output)
                click.echo(click.style(f'Attack tree generated: {output}', fg='green'))
            else:
                click.echo(text_output)
        elif output_format == 'dot':
            graph = generator.to_graphviz()
            if output:
                Path(output).write_text(graph.source)
                click.echo(click.style(f'Attack tree generated: {output}', fg='green'))
            else:
                click.echo(graph.source)
        else:
            if output:
                output_file = generator.render_to_file(output, output_format)
                click.echo(click.style(f'Attack tree generated: {output_file}', fg='green'))
            else:
                output_path = Path(model_path) / 'reports' / 'attack-tree'
                output_file = generator.render_to_file(str(output_path), output_format)
                click.echo(click.style(f'Attack tree generated: {output_file}', fg='green'))
        
    except ThreatModelParseError as e:
        click.echo(click.style(f'Failed to generate attack tree: {e}', fg='red'), err=True)
        sys.exit(1)


@cli.command()
@click.argument('models_root', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--output-dir', '-o', type=click.Path(), help='Output directory for all reports')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def batch(models_root: str, output_dir: str, verbose: bool):
    """Generate reports for all threat models in a directory (recursive)."""
    models_root_path = Path(models_root).resolve()
    model_infos = discover_threat_models(models_root)
    
    if not model_infos:
        click.echo(click.style('No threat models found.', fg='yellow'))
        return
    
    click.echo(f'Found {len(model_infos)} threat model(s)')
    if verbose:
        click.echo(f'[INFO] Models root: {models_root_path}')
    
    # Load all models first
    all_models = []
    for model_info in model_infos:
        try:
            model = load_threat_model(model_info['path'])
            model_info['model'] = model
            model_info['title'] = model.meta.title
            model_info['modelId'] = model.meta.modelId
            all_models.append(model_info)
            if verbose:
                click.echo(f'[INFO] Loaded: {model.meta.title} ({model.meta.modelId})')
                click.echo(f'       Threats: {len(model.threats)}, Assets: {len(model.assets)}, Version: {model.meta.version}')
        except ThreatModelParseError as e:
            click.echo(click.style(f'Skipping {model_info["path"]}: {e}', fg='yellow'))
    
    generator = ReportGenerator()
    generated_reports = []
    
    # Generate each report with cross-links
    for model_info in all_models:
        if output_dir:
            output_path = Path(output_dir) / model_info['rel_path'] / 'reports' / 'threat-model.html'
        else:
            output_path = model_info['path'] / 'reports' / 'threat-model.html'
        
        # Build simple navigation list with correct relative paths
        nav_models = []
        for other in all_models:
            rel_path = calculate_relative_path(
                model_info['path'], 
                other['path'], 
                models_root_path
            )
            nav_models.append({
                'title': other['title'],
                'modelId': other['modelId'],
                'path': rel_path,
                'isCurrent': (other['modelId'] == model_info['modelId'])
            })

        generator.generate_to_file(
            model_info['model'], 
            output_path, 
            nav_models
        )
        
        generated_reports.append({
            'title': model_info['title'],
            'output_path': output_path.resolve(),
            'threats': len(model_info['model'].threats),
            'assets': len(model_info['model'].assets)
        })
        
        if verbose:
            click.echo(click.style(f'  ✓ {model_info["title"]}', fg='green'))
            click.echo(f'    Output: {output_path.resolve()}')
            click.echo(f'    Threats: {len(model_info["model"].threats)}, Assets: {len(model_info["model"].assets)}')
        else:
            click.echo(click.style(f'  ✓ {model_info["title"]}', fg='green'))
    
    # Final summary
    click.echo(click.style(f'\n{"="*60}', fg='cyan'))
    click.echo(click.style('Batch Report Generation Summary', fg='cyan', bold=True))
    click.echo(click.style(f'{"="*60}', fg='cyan'))
    
    total_threats = sum(r['threats'] for r in generated_reports)
    total_assets = sum(r['assets'] for r in generated_reports)
    
    click.echo(f'Total Reports Generated: {len(generated_reports)}')
    click.echo(f'Total Threats Analyzed: {total_threats}')
    click.echo(f'Total Assets Mapped: {total_assets}')
    
    click.echo(f'\nIndividual Report Outputs:')
    
    for report in generated_reports:
        click.echo(f'  • {report["title"]}')
        click.echo(f'    Path: {report["output_path"]}')
        click.echo(f'    Stats: {report["threats"]} threats, {report["assets"]} assets')
    
    click.echo(click.style(f'\n{"="*60}', fg='cyan'))
    click.echo(click.style(f'Done! {len(all_models)} individual report(s) generated.', fg='green', bold=True))


@cli.command()
@click.argument('model_path', type=click.Path(exists=False))
@click.option('--title', '-t', prompt='Threat model title', help='Title for the threat model')
@click.option('--model-id', '-i', prompt='Model ID', help='Unique identifier')
@click.option('--scope', '-s', prompt='Scope description', help='Description of what is being modeled')
@click.option('--owner', '-w', default='', help='Owner of the threat model')
def init(model_path: str, title: str, model_id: str, scope: str, owner: str):
    """Initialize a new threat model folder with template files."""
    model_dir = Path(model_path)
    
    if model_dir.exists():
        click.echo(click.style(f'Directory already exists: {model_path}', fg='red'), err=True)
        sys.exit(1)
    
    model_dir.mkdir(parents=True)
    (model_dir / 'reports').mkdir()
    
    meta_content = f'''title: "{title}"
modelId: "{model_id}"
version: "1.0.0"
scope: "{scope}"
owner: "{owner or 'TBD'}"
lastUpdated: "{datetime.now().strftime('%Y-%m-%d')}"
'''
    (model_dir / '_meta.yaml').write_text(meta_content)
    
    assets_content = '''assets: []
'''
    (model_dir / 'assets.yaml').write_text(assets_content)
    
    attackers_content = '''attackers: []
'''
    (model_dir / 'attackers.yaml').write_text(attackers_content)
    
    objectives_content = '''securityObjectives: []
'''
    (model_dir / 'security-objectives.yaml').write_text(objectives_content)
    
    threats_content = '''threats: []
'''
    (model_dir / 'threats.yaml').write_text(threats_content)
    
    click.echo(click.style('Threat model initialized successfully!', fg='green'))
    click.echo(f'  Location: {model_dir}')
    click.echo(f'\nCreated files:')
    click.echo(f'  - _meta.yaml')
    click.echo(f'  - assets.yaml')
    click.echo(f'  - attackers.yaml')
    click.echo(f'  - security-objectives.yaml')
    click.echo(f'  - threats.yaml')
    click.echo(f'\nNext steps:')
    click.echo(f'  1. Define your assets and data flows in assets.yaml')
    click.echo(f'  2. Define attacker profiles in attackers.yaml')
    click.echo(f'  3. Define security objectives in security-objectives.yaml')
    click.echo(f'  4. Add threats and countermeasures in threats.yaml')
    click.echo(f'  5. Run: python -m src.cli validate {model_path}')
    click.echo(f'  6. Run: python -m src.cli report {model_path}')


@cli.command()
@click.argument('output_path', type=click.Path())
@click.option('--transcript', '-t', type=click.Path(exists=True), help='Path to transcript file')
@click.option('--context', '-c', type=click.Path(exists=True), help='Path to product context file')
@click.option('--title', prompt='Threat model title', help='Title for the threat model')
@click.option('--model-id', '-i', prompt='Model ID', help='Unique identifier')
@click.option('--owner', '-w', default='Security Team', help='Owner of the threat model')
@click.option('--generate-report/--no-report', default=True, help='Auto-generate HTML report')
def analyze(output_path: str, transcript: str, context: str, title: str, model_id: str, owner: str, generate_report: bool):
    """Analyze a transcript to auto-generate a threat model."""
    output_dir = Path(output_path)
    
    if output_dir.exists():
        if not click.confirm(f'Directory {output_path} exists. Overwrite?'):
            click.echo('Aborted.')
            return
    
    if transcript:
        transcript_text = Path(transcript).read_text(encoding='utf-8')
        click.echo(f'Loaded transcript: {transcript}')
    else:
        click.echo('Enter transcript text (end with Ctrl+Z on Windows or Ctrl+D on Unix):')
        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass
        transcript_text = '\n'.join(lines)
    
    if context:
        context_text = Path(context).read_text(encoding='utf-8')
        click.echo(f'Loaded context: {context}')
    else:
        context_text = click.prompt('Enter product context', default='')
    
    if not transcript_text.strip() and not context_text.strip():
        click.echo(click.style('No input provided.', fg='red'), err=True)
        sys.exit(1)
    
    click.echo('\nAnalyzing input...')
    generator = ThreatModelGenerator(output_dir)
    
    try:
        model_path = generator.generate_from_input(
            transcript=transcript_text,
            product_context=context_text,
            title=title,
            model_id=model_id,
            owner=owner
        )
        
        click.echo(click.style('Threat model generated!', fg='green'))
        click.echo(f'  Location: {model_path}')
        
        click.echo('\nValidating generated model...')
        model = load_threat_model(model_path)
        click.echo(click.style('Validation passed!', fg='green'))
        click.echo(f'  Assets: {len(model.assets)}')
        click.echo(f'  Threats: {len(model.threats)}')
        click.echo(f'  Countermeasures: {sum(len(t.countermeasures) for t in model.threats)}')
        
        if generate_report:
            click.echo('\nGenerating HTML report...')
            report_path = model_path / 'reports' / 'threat-model.html'
            report_generator = ReportGenerator()
            report_generator.generate_to_file(model, report_path)
            click.echo(click.style('Report generated!', fg='green'))
            click.echo(f'  Report: {report_path}')
        
    except Exception as e:
        click.echo(click.style(f'Error: {e}', fg='red'), err=True)
        sys.exit(1)


def main():
    """Entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()
