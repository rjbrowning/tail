"""
TAIL - Threat Actor Intelligence Lookup
Flask application for searching and displaying ransomware threat group intelligence.

This application provides:
- Search functionality across threat groups, aliases, TTPs, sectors, and victims
- Advanced filtering by sector, country, TTP, and date ranges
- Detailed threat group profiles with incident history
"""

# Standard library imports
from flask import Flask, render_template, request, jsonify
import sqlite3
import os

 # Flask application setup
app = Flask(__name__, template_folder="templates", static_folder="static")
DATABASE = 'ransomware_research.db'

# Database connection helper
def get_db_connection():
    """
    Establish a connection to the SQLite database.
    
    Returns:
        sqlite3.Connection: Database connection with row_factory set to sqlite3.Row
                           for dictionary-like access to rows
                           
    Security: Uses parameterised queries throughout to prevent SQL injection
    """
    conn = sqlite3.connect(DATABASE)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn

# Query helper function
def query_db(query, args=(), one=False):
    """
    Execute a database query and return results.
    
    Args:
        query (str): SQL query string to execute
        args (tuple): Query parameters for parameterised queries
        one (bool): If True, return only the first result; if False, return all results
    
    Returns:
        sqlite3.Row or list: Single row if one=True, list of rows otherwise
        
    Security: All queries must use parameterised statements with bound variables
    """
    conn = get_db_connection()
    cur = conn.execute(query, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

# Route for the main search page
@app.route('/')
def index():
    """
    Render the main search page with filter options.
    
    Retrieves all unique sectors, countries, TTPs, and date ranges from the database
    to populate filter dropdowns.
    
    Returns:
        str: Rendered HTML template for the search page
    """
    conn = get_db_connection()
    
    # Retrieve all unique sectors for the filter dropdown
    sectors = conn.execute('''
        SELECT DISTINCT sector 
        FROM incidents 
        WHERE sector IS NOT NULL AND sector != ''
        ORDER BY sector
    ''').fetchall()
    
    # Retrieve all unique countries for the filter dropdown
    countries = conn.execute('''
        SELECT DISTINCT country 
        FROM incidents 
        WHERE country IS NOT NULL AND country != ''
        ORDER BY country
    ''').fetchall()
    
    # Retrieve all TTPs (MITRE ATT&CK techniques) for the filter dropdown
    # Uses attack_id and title concatenation for display
    ttps = conn.execute('''
        SELECT DISTINCT attack_id || ' ' || title as ttp_name
        FROM ttps
        ORDER BY attack_id
    ''').fetchall()
    
    # Get the earliest and latest incident dates for date range inputs
    date_range = conn.execute('''
        SELECT MIN(incident_date) as min_date, MAX(incident_date) as max_date
        FROM incidents
        WHERE incident_date IS NOT NULL AND incident_date != ''
    ''').fetchone()
    
    conn.close()
    
    return render_template(
        'index.html',
        sectors=[s['sector'] for s in sectors],
        countries=[c['country'] for c in countries],
        ttps=[t['ttp_name'] for t in ttps],
        min_date=date_range['min_date'] if date_range else None,
        max_date=date_range['max_date'] if date_range else None
    )

# Route to handle search requests
@app.route('/search', methods=['POST'])
def search():
    """
    Search for threat groups based on provided filters.
    
    Accepts JSON payload with the following optional filters:
    - query: Text search across group names, aliases, sectors, TTPs, and victim names
    - sector: Filter by specific victim sector
    - country: Filter by specific victim country
    - ttp: Filter by specific MITRE ATT&CK technique
    - date_from: Filter incidents from this date onwards
    - date_to: Filter incidents up to this date
    
    Returns:
        JSON: Array of matching threat groups with:
            - group_id: Unique identifier for the group
            - group_name: Primary name of the threat group
            - incident_count: Number of recorded incidents
            - sectors: List of targeted sectors
            - countries: List of targeted countries
            - match_reasons: List of fields that matched the search query
            - first_incident: Date of earliest incident
            - last_incident: Date of most recent incident
            
    Security: Uses parameterised queries to prevent SQL injection attacks
    """
    # Parse JSON request body
    data = request.get_json()
    query = data.get('query', '').strip()
    sector_filter = data.get('sector', '').strip()
    country_filter = data.get('country', '').strip()
    ttp_filter = data.get('ttp', '').strip()
    date_from = data.get('date_from', '').strip()
    date_to = data.get('date_to', '').strip()
    
    conn = get_db_connection()
    
    # Build SQL query with match tracking to show why results matched
    # This query aggregates data across multiple tables:
    # - groups: threat group information
    # - incidents: recorded attacks
    # - group_aliases: alternative names for groups
    # - incident_ttps: linking table for TTPs used in incidents
    # - ttps: MITRE ATT&CK techniques
    sql = '''
        SELECT 
            g.id AS group_id,
            g.name AS group_name,
            COUNT(DISTINCT i.id) AS incident_count,
            GROUP_CONCAT(DISTINCT i.sector) AS sectors,
            GROUP_CONCAT(DISTINCT i.country) AS countries,
            MAX(CASE WHEN g.name LIKE ? THEN 1 ELSE 0 END) AS matched_name,
            MAX(CASE WHEN ga.alias LIKE ? THEN 1 ELSE 0 END) AS matched_alias,
            MAX(CASE WHEN i.sector LIKE ? THEN 1 ELSE 0 END) AS matched_sector,
            MAX(CASE WHEN (t.attack_id || ' ' || t.title) LIKE ? THEN 1 ELSE 0 END) AS matched_ttp,
            MAX(CASE WHEN i.victim_name LIKE ? THEN 1 ELSE 0 END) AS matched_victim,
            GROUP_CONCAT(DISTINCT CASE WHEN ga.alias LIKE ? THEN ga.alias END) AS matching_aliases,
            MIN(i.incident_date) AS first_incident,
            MAX(i.incident_date) AS last_incident
        FROM groups g
        LEFT JOIN incidents i ON g.id = i.group_id
        LEFT JOIN group_aliases ga ON g.id = ga.group_id
        LEFT JOIN incident_ttps it ON i.id = it.incident_id
        LEFT JOIN ttps t ON it.ttp_id = t.id
        WHERE 1=1
    '''
    
    params = []
    search_pattern = f'%{query}%' if query else '%'
    
    # Add parameters for match detection (used to show why results matched)
    params.extend([search_pattern] * 6)
    
    # Apply text search filter if query is provided
    if query:
        sql += '''
            AND (
                g.name LIKE ? 
                OR ga.alias LIKE ?
                OR i.sector LIKE ?
                OR (t.attack_id || ' ' || t.title) LIKE ?
                OR i.victim_name LIKE ?
            )
        '''
        params.extend([search_pattern] * 5)
    
    # Apply sector filter
    if sector_filter:
        sql += ' AND i.sector = ?'
        params.append(sector_filter)
    
    # Apply country filter
    if country_filter:
        sql += ' AND i.country = ?'
        params.append(country_filter)
    
    # Apply TTP filter (matches against concatenated attack_id and title)
    if ttp_filter:
        sql += ' AND (t.attack_id || \' \' || t.title) = ?'
        params.append(ttp_filter)
    
    # Apply date range filters
    if date_from:
        sql += ' AND i.incident_date >= ?'
        params.append(date_from)
    
    if date_to:
        sql += ' AND i.incident_date <= ?'
        params.append(date_to)
    
    # Group by threat group and order by activity level
    sql += '''
        GROUP BY g.id, g.name
        HAVING incident_count > 0
        ORDER BY incident_count DESC, g.name ASC
    '''
    
    results = conn.execute(sql, params).fetchall()
    conn.close()
    
    # Format results for JSON response
    groups = []
    for row in results:
        # Parse comma-separated sector and country lists
        sectors_list = row['sectors'].split(',') if row['sectors'] else []
        countries_list = row['countries'].split(',') if row['countries'] else []
        
        # Remove duplicates and None values, then sort
        sectors_list = sorted(list(set(filter(None, sectors_list))))
        countries_list = sorted(list(set(filter(None, countries_list))))
        
        # Build list of match reasons to show user why this result appeared
        match_reasons = []
        if row['matched_name']:
            match_reasons.append('Group Name')
        if row['matched_alias'] and row['matching_aliases']:
            aliases = [a for a in row['matching_aliases'].split(',') if a]
            # Show up to 2 matching aliases
            match_reasons.append(f"Alias: {', '.join(aliases[:2])}")
        if row['matched_sector']:
            match_reasons.append('Sector')
        if row['matched_ttp']:
            match_reasons.append('TTP')
        if row['matched_victim']:
            match_reasons.append('Victim Name')
        
        groups.append({
            'group_id': row['group_id'],
            'group_name': row['group_name'],
            'incident_count': row['incident_count'],
            'sectors': sectors_list,
            'countries': countries_list,
            'match_reasons': match_reasons,
            'first_incident': row['first_incident'],
            'last_incident': row['last_incident']
        })
    
    return jsonify(groups)

# Route for detailed threat group profile
@app.route('/group/id/<int:group_id>')
def group_details(group_id):
    """
    Display detailed information for a specific threat group.
    
    Args:
        group_id (int): Unique identifier for the threat group
    
    Returns:
        str: Rendered HTML template with group details, or 404 if group not found
        
    Template variables:
        summary (dict): Group profile information including aliases, motivation,
                       targeted industries/countries, victim count, dates, and TTPs
        incidents (list): List of all incidents attributed to this group, with
                         victim info, sector, country, date, data exposed, and TTPs used
                         Ordered by completeness (most complete incidents first)
    """
    conn = get_db_connection()
    
    # Retrieve basic group information
    group = conn.execute('''
        SELECT id, name, synopsis, motivation, total_victims
        FROM groups
        WHERE id = ?
    ''', (group_id,)).fetchone()
    
    # Return 404 if group doesn't exist
    if not group:
        conn.close()
        return "Group not found", 404
    
    # Get all known aliases for this group
    aliases = conn.execute('''
        SELECT alias FROM group_aliases WHERE group_id = ? ORDER BY alias
    ''', (group_id,)).fetchall()
    
    # Build list of all names (primary name + aliases)
    alias_list = [group['name']] + [a['alias'] for a in aliases]
    
    # Get list of targeted countries directly from incidents table
    countries = conn.execute('''
        SELECT DISTINCT country 
        FROM incidents
        WHERE group_id = ? AND country IS NOT NULL AND country != ''
        ORDER BY country
    ''', (group_id,)).fetchall()
    
    regions = ', '.join([c['country'] for c in countries]) if countries else 'N/A'
    
    # Get list of targeted industries directly from incidents table
    industries = conn.execute('''
        SELECT DISTINCT sector 
        FROM incidents
        WHERE group_id = ? AND sector IS NOT NULL AND sector != ''
        ORDER BY sector
    ''', (group_id,)).fetchall()
    
    industries_str = ', '.join([i['sector'] for i in industries]) if industries else 'N/A'
    
    # Get activity timeline from the group_activity_summary view
    activity = conn.execute('''
        SELECT first_incident, last_incident, total_incidents
        FROM group_activity_summary
        WHERE group_id = ?
    ''', (group_id,)).fetchone()
    
    first_seen = activity['first_incident'] if activity and activity['first_incident'] else 'N/A'
    last_seen = activity['last_incident'] if activity and activity['last_incident'] else 'N/A'
    
    # Get all unique TTPs used by this group across all incidents
    group_ttps = conn.execute('''
        SELECT DISTINCT t.attack_id || ' ' || t.title as ttp_name
        FROM ttps t
        JOIN incident_ttps it ON t.id = it.ttp_id
        JOIN incidents i ON it.incident_id = i.id
        WHERE i.group_id = ?
        ORDER BY t.attack_id
    ''', (group_id,)).fetchall()
    
    mitre_ttps = ', '.join([t['ttp_name'] for t in group_ttps]) if group_ttps else 'N/A'
    """
    Retrieve all incidents attributed to this group with completeness scoring
    Get all incidents attributed to this group with completeness scoring
    Completeness score prioritises incidents with more data populated:
     - 1 point per populated field (sector, data_exposed, source_url)
     - 0.1 point per 100 characters in data_exposed (rewards detailed descriptions)
     - 0.5 points per associated TTP (rewards documented techniques)
    Ensures the most informative incidents appear first"""

    incidents_raw = conn.execute('''
        SELECT 
            i.id,
            i.victim_name,
            i.sector,
            i.country,
            i.incident_date,
            i.data_exposed,
            i.source_url,
            -- Calculate completeness score based on populated fields
            (
                -- Count non-empty fields (each worth 1 point)
                CASE WHEN i.sector IS NOT NULL AND i.sector != '' THEN 1 ELSE 0 END +
                CASE WHEN i.data_exposed IS NOT NULL AND i.data_exposed != '' THEN 1 ELSE 0 END +
                CASE WHEN i.source_url IS NOT NULL AND i.source_url != '' THEN 1 ELSE 0 END +
                -- Bonus points for detailed data_exposed descriptions (0.1 point per 100 chars)
                (LENGTH(COALESCE(i.data_exposed, '')) / 100.0) +
                -- Count associated TTPs (each TTP worth 0.5 points)
                (SELECT COUNT(*) * 0.5 FROM incident_ttps it2 WHERE it2.incident_id = i.id)
            ) AS completeness_score
        FROM incidents i
        WHERE i.group_id = ?
        -- Order by completeness first (most complete incidents at top), then by date
        ORDER BY completeness_score DESC, i.incident_date DESC
    ''', (group_id,)).fetchall()
    
    # Build detailed incident list with TTPs for each incident
    incidents = []
    for inc in incidents_raw:
        # Get TTPs specific to this incident
        incident_ttps = conn.execute('''
            SELECT t.attack_id || ' ' || t.title as ttp_name
            FROM ttps t
            JOIN incident_ttps it ON t.id = it.ttp_id
            WHERE it.incident_id = ?
            ORDER BY t.attack_id
        ''', (inc['id'],)).fetchall()
        
        incident_ttps_str = ', '.join([t['ttp_name'] for t in incident_ttps]) if incident_ttps else 'N/A'
        
        # Build incident dictionary
        incidents.append({
            'victim_name': inc['victim_name'] or 'Unknown Victim',
            'victim_sector': inc['sector'] or 'N/A',
            'victim_country': inc['country'] or 'N/A',
            'date_of_leak': inc['incident_date'] or 'N/A',
            'data_exposed': inc['data_exposed'] or 'N/A',
            'mitre_ttps': incident_ttps_str,
            'source_url': inc['source_url']
        })
    
    conn.close()
    
    # Build summary dictionary for template
    summary = {
        'group_name': group['name'],
        'aliases': ', '.join(alias_list[1:]) if len(alias_list) > 1 else 'N/A',  # Exclude primary name
        'synopsis': group['synopsis'] or 'No synopsis available.',
        'motivation': group['motivation'] or 'N/A',
        'regions': regions,
        'industries': industries_str,
        'mitre_ttps': mitre_ttps,
        'total_victims': str(group['total_victims']) if group['total_victims'] else '0',
        'first_seen': first_seen,
        'last_seen': last_seen
    }
    
    return render_template('group_details.html', summary=summary, incidents=incidents)

# Run the Flask app 
if __name__ == '__main__':
    app.run(
        host="0.0.0.0", 
        port=int(os.environ.get("PORT", "5000")), 
        debug=os.environ.get("FLASK_DEBUG") == "1"
    )