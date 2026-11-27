"""The registered sites of one data folder: <data>/sites/<site id>/, one folder per site (unchanged layout; a single-site folder needs no migration).

Every site keeps its own settings, permits, grants, Baselines, runs, history and notifications inside its folder. Nothing here moves or rewrites
a site. A folder is a site only when its name IS the site id its own site.json states (a copied or renamed folder is reported, never used), so one
site's permits and history can never be picked up under another site's name. Tools never guess between several sites: resolve() refuses.

Pages: the first page of a site IS the site folder (unchanged). Further pages of the same host are whole units of their own in
<site>/pages/<site id>-p2 .. -p5 (same layout as a site folder: site.json, settings, grant, workspace, runs, Baselines, history, notices), so two pages
never share anything by accident and a signed permit or grant -- which names one path -- never covers another page. Shared on purpose, read from the
site folder: the ownership evidence (it is about the host) and the e-mail switch; from the data folder: the trust file.
"""
import json
from pathlib import Path
import re

SITE_ID = re.compile(r'site-[0-9a-f]{8}\Z')
PAGE_ID = re.compile(r'(site-[0-9a-f]{8})-p([2-9])\Z')
MAX_PAGES = 5  # per site, the first page included


class SiteUnknown(ValueError):
    pass


def scan(data):
    """-> (usable site folders, sorted by registration time, [(folder name, why it is not used)])."""
    root = Path(data) / 'sites'
    good, bad = [], []
    for p in sorted(root.iterdir()) if root.is_dir() else []:
        if not p.name.startswith('site-') or not (p / 'site.json').is_file():
            continue
        try:
            info = json.loads((p / 'site.json').read_text('utf-8'))
            if not SITE_ID.match(p.name) or info.get('site_id') != p.name:
                raise ValueError('フォルダ名とsite.jsonのsite_idが一致しません')
            good.append((str(info.get('registered_at') or ''), p.name, p))
        except (OSError, ValueError, AttributeError) as exc:
            bad.append((p.name, str(exc)[:120]))
    return [p for _, _, p in sorted(good)], bad


def folders(data):
    return scan(data)[0]


def resolve(data, site_id=None):
    """-> the folder of `site_id`; without one, of the only registered site. Several sites and no id: refused (never "the first one")."""
    found = folders(data)
    if site_id is not None:
        for p in found:
            if p.name == site_id:
                return p
        raise SiteUnknown(f'登録されていないサイトです：{site_id}')
    if not found:
        raise SiteUnknown('サイトが登録されていません')
    if len(found) > 1:
        raise SiteUnknown('サイトが複数登録されています。--site で指定してください：' + ' / '.join(p.name for p in found))
    return found[0]


def site_root_of(unit_root):
    """The site folder of a unit (a site folder itself, or <site>/pages/<page id>)."""
    root = Path(unit_root).resolve()
    return root.parents[1] if root.parent.name == 'pages' and PAGE_ID.match(root.name) and SITE_ID.match(root.parents[1].name) else root


def data_of(unit_root):
    """<data> of a unit folder."""
    return site_root_of(unit_root).parents[1]


def unit_problem(unit_root, info):
    """None, or why this folder is not the unit its site.json says it is (copied, renamed, moved to another site, another host)."""
    root = Path(unit_root).resolve()
    site = site_root_of(root)
    try:
        if not SITE_ID.match(site.name) or info['site_id'] != site.name or not isinstance(info['url'], str):
            return 'フォルダ名とsite.jsonのsite_idが一致しません'
        if site != root:
            m = PAGE_ID.match(root.name)
            first = json.loads((site / 'site.json').read_text('utf-8'))
            if m.group(1) != site.name or info.get('page_id') != root.name or info.get('origin') != first.get('origin') or not info['url'].startswith(first['origin'] + '/'):
                return 'ページの登録内容がサイトと一致しません'
            if info['url'] == first.get('url'):
                return '最初のページと同じURLです'
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return 'サイトの登録内容を確認できません'
    return None


def pages(site_root):
    """-> (usable page folders of a site, in order, [(folder name, why it is not used)]). The first page (the site folder) is not in the list."""
    folder = Path(site_root) / 'pages'
    good, bad, urls = [], [], set()
    for p in sorted(folder.iterdir()) if folder.is_dir() else []:
        if not (p / 'site.json').is_file() or p.name.startswith('.'):
            continue
        try:
            info = json.loads((p / 'site.json').read_text('utf-8'))
            why = unit_problem(p, info) or ('同じURLのページが重複しています' if info['url'] in urls else None)
        except (OSError, ValueError, KeyError, TypeError):
            why = 'サイトの登録内容を確認できません'
        if why is None and PAGE_ID.match(p.name):
            urls.add(info['url'])
            good.append(p)
        else:
            bad.append((p.name, why or 'フォルダ名が不正です'))
    return good, bad


def units(site_root):
    """Every monitored unit of a site: the first page (the site folder), then its further pages."""
    return [Path(site_root), *pages(site_root)[0]]


def resolve_unit(data, site_id=None, page_id=None):
    """-> the unit folder: the site's first page, or the named further page of that site."""
    site = resolve(data, site_id)
    if page_id is None:
        return site
    for p in pages(site)[0]:
        if p.name == page_id:
            return p
    raise SiteUnknown(f'登録されていないページです：{page_id}')
