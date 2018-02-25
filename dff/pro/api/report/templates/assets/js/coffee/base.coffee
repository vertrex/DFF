@DFF_DB =
  databases: {}

  setDatabase: (name, db) ->
    DFF_DB.databases[name]=db

  getDatabase: (name) ->
    return DFF_DB.databases[name]


class Generator
  constructor: () ->
    @page = new Page()
    @buildHeader()
    @refresh(@firstCategory(), @firstPage(@firstCategory()).title)
  
  firstCategory: () ->
    for category, pages of DFF_REPORT_INDEX
      return category

  firstPage: (cname) ->
    for category, pages of DFF_REPORT_INDEX
      if category is cname
        return pages[0]

  getPage: (cname, pname) ->
    for category, pages of DFF_REPORT_INDEX when category is cname
      for page in pages when page.title is pname
        return page

  buildHeader: () ->
    $('ul.nav#categories').empty()
    for category, pages of DFF_REPORT_INDEX
      $('ul.nav#categories').append $('<li>').append $('<a>').attr('href', '#').append category

  refresh : (cname, pname) ->
    @refreshNavigation(cname, pname)
    @page.refresh(@getPage(cname, pname))

  refreshNavigation: (cname, pname) ->
    $('ul.nav#pages').empty()
    pages_ul = $('ul.nav#pages')
    for category, pages of DFF_REPORT_INDEX
      head = $('<li>').addClass('nav-header').append(category)
      pages_ul.append(head)
      for page in pages
        if page.title is pname and category is cname
          page_li = $('<li>').addClass 'active'
        else
          page_li = $('<li>')
        pages_ul.append page_li.append $('<a>')
          .attr('href', '#').attr('category', category)
          .append(page.title)

$ ->
  gen = new Generator

  $('ul.nav#categories').bind 'click', (event) ->
    cname = $(event.target).text()
    if cname
      gen.refresh(cname, gen.firstPage(cname).title)
#      page = new Page(gen.page(cname, gen.firstPage(cname).title))

  $('ul.nav#pages').bind 'click', (event) ->
    pname = $(event.target).text()
    cname = $(event.target).attr('category')
    if cname and pname
      gen.refresh(cname, pname)
#      page = new Page(gen.page(cname, pname))

        



  