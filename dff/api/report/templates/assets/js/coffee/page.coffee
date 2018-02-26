class @Page
  constructor: ->
    @script_count = $('script').length
    @fmanager = new fragments.Manager()
    @db = null
  
  cleanPreviousScripts: () ->
    scripts = $('script')
    for script, i in scripts
      $(script).remove() if i >= @script_count

  loadScript: (url) ->
    @db = url
    script = document.createElement 'script'
    script.type = 'text/javascript'
    if script.readyState
      script.onreadystatechange = () ->
        if script.readyState in ['loaded', 'complete']
          script.onreadystatechange = null
          @refreshFragments()
    else
      script.onload = @refreshFragments
    script.src = url
    document.getElementsByTagName('head')[0].appendChild(script)

  refreshFragments : () =>
    if @db
      frags = DFF_DB.getDatabase(@db)
      @fmanager.clearAll()
      for frag in frags
#        console.log frag
        @fmanager.create frag
      @fmanager.renderAll($('div.span9#content'))
  
  refresh: (page) ->
    @cleanPreviousScripts()
    @loadScript(page.content)



